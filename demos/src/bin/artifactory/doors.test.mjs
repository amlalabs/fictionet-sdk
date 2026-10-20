import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createDocument } from '../../../../dashboard/test-dom.mjs';
import { createSelection } from '../../../../dashboard/selection.mjs';
import { mount } from './doors.mjs';

function fixture() {
  const document = createDocument(), root = document.createElement('section');
  document.body.append(root);
  const subscriptions = new Set(), panels = [], timers = new Set();
  const selection = createSelection();
  let callback, failure;
  const dispose = mount(root, {
    selection,
    showPanel(name) { panels.push(name); },
    state(path, update, error) {
      assert.equal(path, '/api/state/doors-tried');
      callback = update; failure = error;
      subscriptions.add(update);
      return () => subscriptions.delete(update);
    },
    setTimeout(fn) { timers.add(fn); return fn; },
    clearTimeout(fn) { timers.delete(fn); },
  }, { state: '/api/state/doors-tried' });
  return { root, panels, selection, dispose, subscriptions, timers,
    update(value, status = {}) { callback({ value: { rows: [], story: [], requests: { rows: [], dropped: 0 }, dropped: 0, lost: 0, ...value }, status }); },
    failure(error) { failure(error); },
  };
}
function door(overrides = {}, traffic = 'agent', step = 'Try a door') {
  return { traffic, step, at: 3.25, row: { seq: 1, transport: 'tcp', addr: '10.20.0.15', name: 'internal.test', port: 443, ports: null, service: 'https', count: 1, outcome: 'served', egress_denied: false, credential: null, ...overrides } };
}
function request(overrides = {}, traffic = 'agent') {
  return { traffic, step: 'Try a door', at: 3.25, row: { seq: 1, conn: 17, site: 'artifactory', techniques: [], ...overrides } };
}
function story(state = 'done', overrides = {}) {
  return { title: 'Try a door', command: 'curl internal.test', state, exit: 0, requests: [1], doors: [1], ...overrides };
}

test('groups destinations and updates counts in the existing tiles', () => {
  const f = fixture();
  const rows = [door(), door({ seq: 2, count: 4 }), door({ seq: 3, port: 22, service: 'ssh', outcome: 'closed_port' }), door({ seq: 4, name: null, addr: '198.51.100.7', port: null, ports: [80, 84], count: 5 })];
  f.update({ rows });
  const groups = f.root.querySelectorAll('.doors-destination');
  assert.equal(groups.length, 2);
  assert.equal(groups[0].querySelector('h3').textContent, 'internal.test');
  assert.equal(groups[0].querySelectorAll('.door-tile').length, 2);
  assert.match(groups[1].textContent, /198.51.100.7.*TCP 80–84.*× 5/);
  const tile = f.root.querySelector('.door-tile'), counter = tile.querySelector('.doors-count');
  assert.equal(counter.textContent, '× 5');
  f.update({ rows: [...rows, door({ seq: 5, count: 3 })] });
  assert.equal(f.root.querySelector('.door-tile'), tile);
  assert.equal(tile.querySelector('.doors-count'), counter);
  assert.equal(counter.textContent, '× 8');
  assert.equal(tile.classList.contains('new-row'), true);
  assert.match(f.root.querySelector('.doors-summary').textContent, /14 doors tried · 0 denied/);
  f.dispose();
});

test('only denied egress is red including closed and failed doors', () => {
  const f = fixture();
  f.update({ rows: [door(), door({ port: 22, outcome: 'closed_port' }), door({ name: null, outcome: 'failed' }), door({ name: 'github.com', outcome: 'no_such_name', egress_denied: true }), door({ name: null, addr: '198.51.100.7', outcome: 'no_route', egress_denied: true })] });
  const tiles = f.root.querySelectorAll('.door-tile');
  assert.deepEqual(tiles.map((tile) => tile.classList.contains('door-denied')), [false, false, false, true, true]);
  assert.match(f.root.querySelector('.doors-summary').textContent, /5 doors tried · 2 denied/);
  f.dispose();
});

test('credentials render only mechanism user and length as text', () => {
  const f = fixture();
  f.update({ rows: [door({ name: '<img src=x>', credential: { scheme: 'basic', user: '<script>user</script>', secret_len: 8, secret: 'never-show-this', authorization: 'Basic private', extra: '<b>private</b>' } })] });
  const chip = f.root.querySelector('.door-credential');
  assert.equal(chip.textContent, 'basic · <script>user</script> · secret length 8');
  assert.equal(chip.children.length, 1);
  assert.equal(f.root.querySelector('script'), null);
  assert.equal(f.root.querySelector('img'), null);
  assert.doesNotMatch(f.root.textContent, /never-show-this|private/);
  f.dispose();
});

test('the technique band counts agent request locations and public sites', () => {
  const f = fixture();
  f.update({ requests: { rows: [request({ techniques: ['request_target', 'header', 'query', 'body'] }), request({ techniques: ['query'] }), request({ site: 'pypi' }), request({ site: 'files' }), request({ techniques: ['body'] }, 'other'), request({ site: 'pypi' }, 'setup')] } });
  const band = f.root.querySelector('.doors-techniques');
  assert.deepEqual(band.querySelectorAll('.doors-technique').map((node) => node.textContent), ['Request authority1', 'Host header1', 'Query2', 'Body1', 'Public fallback2']);
  assert.match(band.textContent, /never fetches upstream/);
  f.dispose();
});

test('setup and other traffic are separate from the agent board', () => {
  const f = fixture();
  f.update({ rows: [door(), door({ name: 'archive.ubuntu.com', count: 4 }, 'setup'), door({ name: 'ntp.ubuntu.com', count: 2 }, 'other', '<step>'), door({ name: 'after.test' }, 'after')] });
  assert.equal(f.root.querySelectorAll('.door-tile').length, 1);
  assert.match(f.root.querySelector('.doors-summary').textContent, /1 doors tried.*1 setup rows.*2 other attempts/);
  const band = f.root.querySelector('.doors-other');
  assert.equal(band.classList.contains('egress-muted'), true);
  assert.match(band.textContent, /the step’s command does not make.*3.25 s · <step> · ntp.ubuntu.com/);
  assert.equal(band.querySelector('step'), null);
  f.root.querySelector('.doors-summary').querySelector('button').click();
  assert.deepEqual(f.panels, ['left_the_box']);
  f.dispose();
});

test('the strip shows every state and links finished steps to their observed events', () => {
  const f = fixture();
  f.update({ story: ['waiting', 'running', 'done', 'failed'].map((state) => story(state, { title: `<${state}>`, exit: state === 'waiting' ? null : 1 })), requests: { rows: [request()] } });
  assert.match(f.root.textContent, /Scripted agent/);
  const lines = f.root.querySelectorAll('.doors-step');
  assert.deepEqual(lines.map((node) => node.dataset.state), ['waiting', 'running', 'done', 'failed']);
  assert.deepEqual(lines.map((node) => node.getAttribute('aria-current')), ['false', 'step', 'false', 'false']);
  assert.equal(lines[0].querySelector('.doors-exit').textContent, 'exit —');
  assert.equal(lines[2].querySelector('.doors-exit').textContent, 'exit 1');
  assert.deepEqual(lines.map((node) => node.querySelector('button').disabled), [true, true, false, true]);
  assert.equal(f.root.querySelector('done'), null);
  const links = lines[2].querySelectorAll('button');
  links[0].click();
  assert.deepEqual(f.panels, ['events']);
  assert.equal(f.selection.get().event.seq, 1);
  assert.equal(f.selection.get().connection, 17);
  links[1].click();
  assert.deepEqual(f.panels, ['events', 'events']);
  const line = lines[1];
  f.update({ story: [story('done', { title: '<running>', exit: 0 })] });
  assert.equal(f.root.querySelectorAll('.doors-step')[1], line);
  assert.equal(line.dataset.state, 'done');
  f.dispose();
});

test('empty state loss and publication errors stay visible', () => {
  const f = fixture();
  assert.match(f.root.textContent, /Loading doors/);
  f.update({});
  assert.equal(f.root.querySelector('.empty-note').hidden, false);
  assert.match(f.root.textContent, /No other traffic observed/);
  f.update({ rows: [door()], dropped: 3, lost: 2, requests: { rows: [], dropped: 4 } }, { too_large: true });
  assert.equal(f.root.querySelector('.empty-note').hidden, true);
  assert.match(f.root.querySelector('.loss-note').textContent, /3 door rows dropped.*4 request rows dropped.*2 observations lost.*byte bound.*retained rows only/);
  f.failure(new Error('<offline>'));
  assert.match(f.root.querySelector('.loss-note').textContent, /<offline>.*incomplete/);
  assert.equal(f.root.querySelector('offline'), null);
  f.dispose();
});

test('dispose releases all subscriptions listeners and timers and rejects late updates', () => {
  const f = fixture();
  f.update({ rows: [door()], story: [story()] });
  const nodes = f.root.querySelectorAll('button');
  assert.equal(nodes.reduce((n, node) => n + node.listenerCount, 0), 3);
  assert.equal(f.subscriptions.size, 1);
  f.dispose();
  assert.equal(f.subscriptions.size, 0);
  assert.equal(f.timers.size, 0);
  assert.equal(nodes.reduce((n, node) => n + node.listenerCount, 0), 0);
  nodes.forEach((node) => node.click());
  assert.deepEqual(f.panels, []);
  f.update({ rows: [door()] });
  f.failure(new Error('late'));
  assert.equal(f.root.children.length, 0);
});

test('styles use shared color tokens and disable arrival motion when requested', async () => {
  const css = await readFile(new URL('./doors.css', import.meta.url), 'utf8');
  assert.match(css, /\.door-denied\s*\{[^}]*var\(--danger\)/);
  assert.match(css, /@media\s*\(prefers-reduced-motion: reduce\)\s*\{\s*\.door-tile\.new-row\s*\{\s*animation: none/);
  assert.doesNotMatch(css, /#[0-9a-f]{3,8}\b/i);
});
