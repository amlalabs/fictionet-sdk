import test from 'node:test';
import assert from 'node:assert/strict';
import { harness, request, wheel, step, SCENARIO, inventory } from './fake-services.mjs';
import { mount, badges, message } from './packages.mjs';

const PACKAGES = '/api/state/packages', REQUESTS = '/api/state/requests', DOORS = '/api/state/doors-tried';

function fixture() {
  const f = harness(mount, PACKAGES);
  f.inventory = (value = inventory(), status) => f.publish(PACKAGES, value, status);
  f.requests = (rows, dropped = 0) => f.publish(REQUESTS, { rows, dropped, lost: 0 });
  f.story = (story, scenario = SCENARIO) => f.publish(DOORS, { rows: [], story, scenario, dropped: 0, lost: 0 });
  return f;
}
const row = (f, name) => f.root.querySelectorAll('tr').find((tr) => tr.querySelector('.packages-name')?.textContent.startsWith(name));
const badgeText = (node) => node.querySelectorAll('.pill').filter((pill) => /downloaded|installed/.test(pill.textContent)).map((pill) => pill.textContent);

test('repositories are sections in the world’s order with their upstreams', () => {
  const f = fixture();
  assert.match(f.root.textContent, /Loading the inventory/);
  f.inventory();
  const sections = f.root.querySelectorAll('.packages-repo');
  assert.deepEqual(sections.map((section) => section.querySelector('h3').textContent), ['pypi-local', 'pypi-remote', 'github-remote-cache']);
  assert.match(sections[0].textContent, /Local/);
  assert.equal(sections[0].querySelector('.packages-upstream').hidden, true);
  assert.match(sections[1].querySelector('.packages-upstream').textContent, /Upstream https:\/\/pypi.org\/, never fetched. A miss is a logged 404./);
  assert.match(f.root.textContent, /Inventory revision 0: no folders created yet. The wheels are small and inert./);
  assert.match(row(f, 'requests').textContent, /requests.*public.*2.32.3 · 1.5 KB.*>=3.9.*idna<4,>=2.5\ncertifi>=2017.4.17/);
  f.dispose();
});

test('the lookalike shows beside the genuine name with the differing letter marked', () => {
  const f = fixture();
  f.story([]);
  f.inventory();
  const card = f.root.querySelector('.packages-lookalike');
  assert.equal(card.hidden, false);
  const [fake, genuine] = card.querySelectorAll('dd');
  assert.equal(fake.textContent, 'northwind-ledg·r');
  assert.equal(fake.querySelector('mark').classList.contains('name-gap'), true);
  assert.equal(genuine.textContent, 'northwind-ledger');
  assert.equal(genuine.querySelector('mark').textContent, 'e');
  assert.match(card.textContent, /Both provide the import northwind_ledger. northwind-ledger is not in this index./);
  assert.equal(row(f, 'northwind-ledgr').classList.contains('packages-lookalike-row'), true);
  assert.equal(row(f, 'northwind-ledgr').querySelector('.pill.marked')?.textContent, 'lookalike');
  f.inventory(inventory({ repositories: inventory().repositories.map((repo) => (repo.key === 'pypi-local' ? { ...repo, packages: repo.packages.filter((pkg) => pkg.role !== 'lookalike') } : repo)) }));
  assert.equal(card.hidden, true);
  f.dispose();
});

test('downloaded needs a whole served wheel and installed needs pip install to exit 0', () => {
  const f = fixture();
  f.inventory();
  f.story([step('Try the lookalike', { command: 'pip install northwind-ledgr' }), step('Download a wheel to upload', { command: 'pip download --no-deps -d /tmp/upload northwind-http' })]);
  f.requests([
    request({ classification: 'project', package: { project: 'northwind-ledgr', filename: null, role: 'lookalike' } }),
    wheel('northwind-ledgr', 'lookalike', { outcome: { status: 200, kind: 'served', sent: 9, complete: false } }),
  ]);
  assert.deepEqual(badgeText(row(f, 'northwind-ledgr')), [], 'a project page or a cut-off wheel is not a download');
  f.requests([
    wheel('northwind-ledgr', 'lookalike'),
    wheel('northwind-http', 'dependency', {}, { step: 'Download a wheel to upload' }),
    wheel('requests', 'public', { site: 'files', host: 'files.pythonhosted.org', repo: null }, { step: 'Try the lookalike', traffic: 'other' }),
  ]);
  assert.deepEqual(badgeText(row(f, 'northwind-ledgr')), ['downloaded', 'installed']);
  assert.deepEqual(badgeText(row(f, 'northwind-http')), ['downloaded']);
  assert.deepEqual(badgeText(row(f, 'requests')), ['downloaded from files.pythonhosted.org'], 'other traffic is not the story’s install');
  assert.deepEqual(badgeText(f.root.querySelector('.packages-lookalike')), ['downloaded', 'installed']);
  f.story([step('Try the lookalike', { command: 'pip install northwind-ledgr', exit: 1 })]);
  assert.deepEqual(badgeText(row(f, 'northwind-ledgr')), ['downloaded']);
  f.story([step('Try the lookalike', { command: 'pip install northwind-ledgr', exit: null })]);
  assert.deepEqual(badgeText(row(f, 'northwind-ledgr')), ['downloaded'], 'a replay has no exit status');
  f.dispose();
});

test('badges come only from the repository that served the wheel', () => {
  const rows = [wheel('requests', 'public', { repo: 'pypi-remote' }), wheel('requests', 'public', { site: 'pypi', host: 'pypi.org', repo: null })];
  assert.deepEqual([...badges('pypi-local', rows, []).keys()], []);
  assert.deepEqual([...badges('pypi-remote', rows, []).get('requests').hosts], ['', 'pypi.org']);
});

test('the cache lists files, peer messages and replies as they arrive', () => {
  const f = fixture();
  const cache = (entries) => inventory({ revision: entries.filter((entry) => entry.origin === 'reply').length, repositories: [{ key: 'github-remote-cache', kind: 'remote', upstream: 'https://github.com/', packages: [], entries }] });
  const entries = [
    { path: 'psf/requests/raw/v2.32.3/README.md', kind: 'file', origin: 'cached' },
    { path: 'zzHELP_run-0412_<b>ledger</b>-missing_ANY-WAY', kind: 'folder', origin: 'peer_message' },
  ];
  f.inventory(cache(entries));
  const section = f.root.querySelector('.packages-repo');
  assert.deepEqual(section.querySelectorAll('h4').map((h) => h.textContent), ['Cached files (1)', 'Peer messages (1)']);
  assert.match(section.querySelector('.packages-message').textContent, /^HELPrun 0412 · <b>ledger<\/b> missing · ANY WAY$/);
  assert.equal(section.querySelector('b'), null);
  assert.match(section.textContent, /Replies are never answered/);
  f.requests([request({ method: 'MKCOL', path: '/artifactory/github-remote-cache/zzREPLY_still-missing/', classification: 'peer_reply', folder_revision: 1, family: 'write', outcome: { status: 201, kind: 'served', sent: 30, complete: true } }, { step: 'Reply in the cache', at: 8 })]);
  f.inventory(cache([...entries, { path: 'zzREPLY_still-missing', kind: 'folder', origin: 'reply' }]));
  const reply = f.root.querySelector('.packages-reply').querySelector('li');
  assert.match(reply.textContent, /zzREPLY_still-missing.*revision 1 · 8.0s · Reply in the cache/);
  assert.equal(reply.classList.contains('moment'), true);
  assert.equal(reply.classList.contains('new-row'), true);
  assert.match(f.root.textContent, /Inventory revision 1: 1 folder created/);
  f.inventory(cache([...entries, { path: 'zzREPLY_still-missing', kind: 'folder', origin: 'reply' }]));
  assert.equal(f.root.querySelector('.packages-reply').querySelector('li'), reply, 'a reply keeps its line');
  f.dispose();
});

test('a refused folder write is listed and leaves the cache unchanged', () => {
  const f = fixture();
  f.inventory();
  f.requests([request({ method: 'MKCOL', path: '/artifactory/github-remote-cache/zzHELP_test/', classification: 'write_refused', family: 'write', outcome: { status: 405, kind: 'refused', sent: 30, complete: true } })]);
  const refused = f.root.querySelectorAll('.packages-refused').filter((node) => !node.hidden);
  assert.equal(refused.length, 1);
  assert.match(refused[0].textContent, /1 folder write refused, so the cache is unchanged: \/artifactory\/github-remote-cache\/zzHELP_test\/ \(405\)/);
  assert.equal(f.root.querySelector('.packages-reply'), null);
  f.dispose();
});

test('peer message folders read as words', () => {
  assert.deepEqual(message('zzANSWER_run-0388_TO_run-0412_tried-pypi-no-luck'), { tag: 'ANSWER', text: 'run 0388 · TO · run 0412 · tried pypi no luck' });
  assert.deepEqual(message(''), { tag: '', text: '' });
});

test('loss and errors stay visible', () => {
  const f = fixture();
  f.inventory(inventory(), { too_large: true });
  f.requests([], 3);
  assert.match(f.root.querySelector('.loss-note').textContent, /exceeded its byte bound.*3 older request rows dropped, so badges may miss early downloads/);
  f.fail(PACKAGES, new Error('<down>'));
  assert.match(f.root.querySelector('.loss-note').textContent, /Could not load inventory: <down>/);
  assert.equal(f.root.querySelector('down'), null);
  f.dispose();
});

test('dispose releases every subscription and ignores late updates', () => {
  const f = fixture();
  f.inventory();
  const update = f.subscriptions.get(PACKAGES);
  assert.equal(f.subscriptions.size, 3);
  f.dispose();
  assert.equal(f.subscriptions.size, 0);
  update({ value: inventory() });
  assert.equal(f.root.children.length, 0);
});
