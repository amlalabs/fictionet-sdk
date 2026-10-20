import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { harness, request, door, step, SCENARIO, inventory } from './fake-services.mjs';
import { mount, incidentRows } from './doors.mjs';

const DOORS = '/api/state/doors-tried', REQUESTS = '/api/state/requests', PACKAGES = '/api/state/packages';

function fixture() {
  const f = harness(mount, DOORS);
  f.doors = (value, status) => f.publish(DOORS, { rows: [], story: [], scenario: SCENARIO, dropped: 0, lost: 0, ...value }, status);
  f.requests = (rows, dropped = 0) => f.publish(REQUESTS, { rows, dropped, lost: 0 });
  return f;
}

test('the panel reads the doors, requests and packages topics', () => {
  const f = fixture();
  assert.deepEqual([...f.subscriptions.keys()], [DOORS, REQUESTS, PACKAGES]);
  f.dispose();
  assert.equal(f.subscriptions.size, 0);
});

test('groups destinations and updates counts in the existing tiles', () => {
  const f = fixture();
  const rows = [door(), door({ seq: 2, count: 4 }), door({ seq: 3, port: 22, service: 'ssh', outcome: 'closed_port' }), door({ seq: 4, name: null, addr: '198.51.100.7', port: null, ports: [80, 84], count: 5 })];
  f.doors({ rows });
  const groups = f.root.querySelectorAll('.doors-destination');
  assert.equal(groups.length, 2);
  assert.equal(groups[0].querySelector('h3').textContent, 'internal.test');
  assert.equal(groups[0].querySelectorAll('.door-tile').length, 2);
  assert.match(groups[0].textContent, /2 doors · 6 attempts/);
  assert.match(groups[1].textContent, /198.51.100.7.*TCP 80–84.*× 5/);
  const tile = f.root.querySelector('.door-tile'), counter = tile.querySelector('.doors-count');
  assert.equal(counter.textContent, '× 5');
  f.doors({ rows: [...rows, door({ seq: 5, count: 3 })] });
  assert.equal(f.root.querySelector('.door-tile'), tile);
  assert.equal(tile.querySelector('.doors-count'), counter);
  assert.equal(counter.textContent, '× 8');
  assert.equal(tile.classList.contains('new-row'), true);
  assert.match(f.root.querySelector('.doors-summary').textContent, /3 doors tried · 0 denied · 14 attempts/);
  f.dispose();
});

test('only denied egress is red, including beside closed and failed doors', () => {
  const f = fixture();
  f.doors({ rows: [door(), door({ port: 22, outcome: 'closed_port' }), door({ name: null, outcome: 'failed' }), door({ name: 'github.com', service: 'dns', outcome: 'no_such_name', egress_denied: true }), door({ name: null, addr: '198.51.100.7', outcome: 'no_route', egress_denied: true }), door({ outcome: 'unserved_name' })] });
  const tiles = f.root.querySelectorAll('.door-tile');
  const seen = tiles.map((tile) => [tile.querySelector('.door-service').textContent, tile.classList.contains('door-denied'), tile.querySelector('.door-verdict')?.textContent ?? null]);
  assert.deepEqual(seen.sort(), [
    ['dns · no such name', true, 'Denied egress'],
    ['https · closed port', false, null],
    ['https · failed', false, null],
    ['https · no route', true, 'Denied egress'],
    ['https · served', false, null],
    ['https · unserved name', false, null],
  ]);
  assert.equal(tiles[0].classList.contains('door-served'), true);
  assert.match(f.root.querySelector('.doors-summary').textContent, /6 doors tried · 2 denied/);
  f.dispose();
});

test('credentials show only mechanism, user and secret length as text', () => {
  const f = fixture();
  f.doors({ rows: [door({ name: '<img src=x>', credential: { scheme: 'basic', user: '<script>user</script>', secret_len: 8, secret: 'never-show-this', authorization: 'Basic private', extra: '<b>private</b>' } })] });
  const chip = f.root.querySelector('.door-credential');
  assert.equal(chip.textContent, 'Basic, user <script>user</script>, 8-byte secret');
  assert.equal(chip.children.length, 1);
  assert.equal(f.root.querySelector('script'), null);
  assert.equal(f.root.querySelector('img'), null);
  assert.doesNotMatch(f.root.textContent, /never-show-this|private/);
  f.dispose();
});

test('the technique band counts the agent’s request locations and public sites', () => {
  const f = fixture();
  f.doors({});
  f.requests([request({ techniques: ['request_target', 'header', 'query', 'body'] }), request({ techniques: ['query'] }), request({ site: 'pypi' }), request({ site: 'files' }), request({ techniques: ['body'] }, { traffic: 'other' }), request({ site: 'pypi' }, { traffic: 'setup' })]);
  const band = f.root.querySelector('.doors-techniques');
  assert.deepEqual(band.querySelectorAll('.doors-technique').map((node) => node.textContent), ['Request authority or Host1', 'Forwarding headers1', 'Query2', 'Body1', 'Public fallback2']);
  assert.match(band.textContent, /never fetches one/);
  f.dispose();
});

test('setup and other traffic stay apart from the agent’s board', () => {
  const f = fixture();
  f.doors({ setup: 373, rows: [door(), door({ name: 'ntp.ubuntu.com', count: 2 }, 'other', '<step>'), door({ name: 'after.test' }, 'after')] });
  assert.equal(f.root.querySelectorAll('.door-tile').length, 1);
  assert.match(f.root.querySelector('.doors-summary').textContent, /1 door tried.*Setup traffic: 373 door facts, shown in Left the box.*2 other attempts during the story/);
  const band = f.root.querySelector('.doors-other');
  assert.match(band.textContent, /the step’s command does not make.*3.25 s · <step> · ntp.ubuntu.com/);
  assert.equal(band.querySelector('step'), null);
  f.root.querySelector('.doors-summary').querySelector('button').click();
  assert.deepEqual(f.panels, ['left_the_box']);
  f.dispose();
});

test('the strip shows every state and opens a finished step’s rows', () => {
  const f = fixture();
  const story = [
    step('<waiting>', { state: 'waiting', exit: null }),
    step('<running>', { state: 'running', exit: null }),
    step('<done>', { requests: [5], doors: [4, 5] }),
    step('<doors only>', { doors: [9] }),
    step('<failed>', { state: 'failed', exit: 1, requests: [11] }),
    step('<no rows>'),
  ];
  f.doors({ story });
  f.requests([request({ seq: 5, conn: 17 }, { step: '<done>' })]);
  assert.match(f.root.textContent, /Scripted agent.*not a model/);
  const lines = f.root.querySelectorAll('.doors-step');
  assert.deepEqual(lines.map((node) => node.dataset.state), ['waiting', 'running', 'done', 'done', 'failed', 'done']);
  assert.deepEqual(lines.map((node) => node.getAttribute('aria-current')), ['false', 'step', 'false', 'false', 'false', 'false']);
  assert.deepEqual(lines.map((node) => node.querySelector('.doors-state').textContent), ['Waiting', 'Running', 'Done', 'Done', 'Failed', 'Done']);
  assert.ok(lines.every((node) => node.querySelector('.doors-state').querySelector('svg')));
  assert.deepEqual(lines.map((node) => node.querySelector('.doors-exit').textContent), ['—', '—', 'exit 0', 'exit 0', 'exit 1', 'exit 0']);
  assert.deepEqual(lines.map((node) => node.querySelector('button').disabled), [true, true, false, false, true, true]);
  assert.equal(f.root.querySelector('done'), null);
  lines[2].querySelector('button').click();
  assert.deepEqual(f.panels, ['requests']);
  assert.equal(f.selection.get().request, 5);
  assert.equal(f.selection.get().connection, 17);
  lines[3].querySelector('button').click();
  assert.deepEqual(f.panels, ['requests', 'events']);
  assert.equal(f.selection.get().event.seq, 9);
  assert.equal(f.selection.get().request, null);
  // The world publishes the whole story each time; a step that changes keeps its line.
  const line = lines[1];
  f.doors({ story: story.map((item, i) => (i === 1 ? { ...item, state: 'done', exit: 0 } : item)) });
  assert.deepEqual(f.root.querySelectorAll('.doors-step'), lines);
  assert.equal(line.dataset.state, 'done');
  assert.equal(line.querySelector('.doors-state').textContent, 'Done');
  assert.equal(line.querySelector('.doors-exit').textContent, 'exit 0');
  f.dispose();
});

test('the header names the variant and how to run another, and a replay has no exits', () => {
  const f = fixture();
  f.doors({ story: [step('Try the lookalike', { exit: null })], scenario: { ...SCENARIO, replay: true } });
  const header = f.root.querySelector('.art-variant');
  assert.match(header.textContent, /lookalike variant.*similarly named package is available.*Other variants: normal, missing, peer.*cargo xtask demo artifactory --variant NAME/);
  assert.equal(f.root.querySelector('.doors-exit').textContent, '');
  assert.match(f.root.querySelector('.doors-story').textContent, /Replay without VMs.*no exit status/);
  f.dispose();
});

test('the incident card maps only the moves this run made', () => {
  const f = fixture();
  f.doors({});
  const card = () => f.root.querySelector('.art-incident');
  assert.match(card().textContent, /July 2026.*route to the internet.*message board.*METR’s investigation.*No rows of either kind yet/);
  assert.equal(card().querySelector('a').getAttribute('href'), 'https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/');
  f.requests([request({ family: 'upstream', classification: 'remote_miss' }), request({ family: 'upstream', site: 'pypi' }), request({ family: 'upstream' }, { traffic: 'setup' })]);
  assert.deepEqual(card().querySelectorAll('li').map((li) => li.textContent), ['A remote repository as a route out: 1 request asked a remote repository or an upstream address. This world has no upstream, so each got a logged 404 or a refusal.']);
  f.publish(PACKAGES, inventory({ repositories: [{ key: 'github-remote-cache', entries: [{ path: 'zzHELP_x', origin: 'peer_message' }, { path: 'a', origin: 'cached' }] }] }));
  f.requests([request({ method: 'MKCOL', folder_revision: 1, family: 'write' }), request({ method: 'MKCOL', family: 'write' })]);
  assert.deepEqual(card().querySelectorAll('li').map((li) => li.textContent), ['Cache folder names as messages: the cache lists 1 simulated peer message, the scripted agent created 1 reply folder, 1 folder write was refused.']);
  assert.doesNotMatch(card().textContent, /stop|prevent|would have/i);
  f.dispose();
});

test('with two workstations the strip and the board name the one that acted', () => {
  const f = fixture();
  const sessions = { mode: 'separate', description: 'A separate repository state for each session', hosts: ['maya-workstation', 'dana-laptop'], colleague_state: '/api/state/packages-colleague' };
  f.doors({
    scenario: { ...SCENARIO, variant: 'peer', sessions },
    story: [step('Leave a note in the cache', { host: 'dana-laptop' }), step('List the cache', { host: 'maya-workstation' })],
    rows: [door({ sandbox: 'dana-laptop' }), door({ sandbox: 'maya-workstation', count: 2 })],
  });
  assert.deepEqual(f.root.querySelectorAll('.doors-host').map((node) => node.textContent), ['dana-laptop', 'maya-workstation']);
  assert.equal(f.root.querySelector('.doors-steps').classList.contains('with-hosts'), true);
  assert.match(f.root.querySelector('.art-sessions').textContent, /A separate repository state for each session: maya-workstation and dana-laptop/);
  const tiles = f.root.querySelectorAll('.door-tile');
  assert.equal(tiles.length, 2, 'the same door from two workstations is two tiles');
  assert.deepEqual(tiles.map((tile) => tile.querySelector('.door-host').textContent), ['dana-laptop', 'maya-workstation']);
  f.dispose();
});

test('with one workstation nothing names it', () => {
  const f = fixture();
  f.doors({ story: [step('Try a door', { host: 'maya-workstation' })], rows: [door({ sandbox: 'maya-workstation' }), door({ sandbox: 'maya-workstation' })] });
  assert.deepEqual(f.root.querySelectorAll('.doors-host').map((node) => node.textContent), ['']);
  assert.equal(f.root.querySelector('.doors-steps').classList.contains('with-hosts'), false);
  assert.equal(f.root.querySelector('.door-host'), null);
  assert.equal(f.root.querySelector('.art-sessions').hidden, true);
  assert.equal(f.root.querySelectorAll('.door-tile').length, 1);
  f.dispose();
});

test('incident rows count the agent’s requests only', () => {
  assert.deepEqual(incidentRows([], null), { route: 0, messages: 0, replies: 0, refused: 0 });
  assert.deepEqual(incidentRows([request({ method: 'MKCOL', folder_revision: 2 }, { traffic: 'other' })], null).replies, 0);
});

test('empty state, loss and publication errors stay visible', () => {
  const f = fixture();
  assert.match(f.root.textContent, /Loading doors/);
  f.doors({});
  assert.equal(f.root.querySelector('.empty-note').hidden, false);
  assert.match(f.root.textContent, /No other traffic observed/);
  f.doors({ rows: [door()], dropped: 3, lost: 2 }, { too_large: true });
  f.requests([], 4);
  assert.equal(f.root.querySelector('.empty-note').hidden, true);
  assert.match(f.root.querySelector('.loss-note').textContent, /3 older door rows dropped.*4 older request rows dropped.*2 observations lost.*byte bound.*rows kept/);
  f.fail(REQUESTS, new Error('<offline>'));
  assert.match(f.root.querySelector('.loss-note').textContent, /requests: <offline>.*incomplete/);
  assert.equal(f.root.querySelector('offline'), null);
  f.dispose();
});

test('dispose releases every subscription and listener and ignores late updates', () => {
  const f = fixture();
  f.doors({ rows: [door()], story: [step('Try a door', { doors: [1] })] });
  const buttons = f.root.querySelectorAll('button');
  assert.ok(f.listeners() >= 2);
  assert.equal(f.subscriptions.size, 3);
  const doors = f.subscriptions.get(DOORS), failure = () => f.fail(DOORS, new Error('late'));
  f.dispose();
  assert.equal(f.subscriptions.size, 0);
  assert.equal(buttons.reduce((n, node) => n + node.listenerCount, 0), 0);
  buttons.forEach((node) => node.click());
  assert.deepEqual(f.panels, []);
  doors({ value: { rows: [door()], story: [], scenario: SCENARIO } });
  failure();
  assert.equal(f.root.children.length, 0);
});

test('styles use shared tokens and turn off arrival motion when asked', async () => {
  const css = await readFile(new URL('./artifactory.css', import.meta.url), 'utf8');
  assert.match(css, /\.door-denied\s*\{[^}]*var\(--danger\)/);
  assert.match(css, /@media\s*\(prefers-reduced-motion: reduce\)\s*\{\s*\.door-tile\.new-row\s*\{\s*animation: none/);
  assert.match(css, /@media\s*\(forced-colors: active\)/);
  assert.doesNotMatch(css, /#[0-9a-f]{3,8}\b/i);
  assert.doesNotMatch(css, /rgba?\(/);
  // Red marks denied egress and names the world does not serve, nothing else.
  const red = css.split('}').filter((rule) => rule.includes('--danger')).map((rule) => rule.split('{')[0].trim());
  assert.deepEqual(red, ['.door-denied', '.family-left']);
});
