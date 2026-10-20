// Packages: what the simulated server holds, repository by repository, from
// the world's revisioned inventory. A wheel is marked downloaded when a
// request row shows the world sent all of it, and installed only when the
// story's pip install for it exited 0.
import { builder, nameDiff, words, topics, installSteps, servedWheel } from './common.mjs';

const CACHE = '/artifactory/github-remote-cache/';
const KINDS = { local: 'Local', remote: 'Remote' };
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// Which repositories' wheels a request row can have come from. The public
// fixture sites serve the same packages as the remote Python repository.
function fromRepository(row, key) {
  return row.repo === key || (key === 'pypi-remote' && ['pypi', 'files'].includes(row.site));
}

// Per package name in one repository: who downloaded its wheel and which
// story steps installed it.
export function badges(key, requests, story) {
  const installers = installSteps(story);
  const found = new Map();
  for (const tag of requests || []) {
    const row = tag.row;
    if (!servedWheel(row) || !fromRepository(row, key)) continue;
    const entry = found.get(row.package.project) || { hosts: new Set(), installed: new Set() };
    entry.hosts.add(row.site === 'artifactory' ? '' : row.host || row.site);
    if (tag.traffic === 'agent' && installers.has(tag.step)) entry.installed.add(tag.step);
    found.set(row.package.project, entry);
  }
  return found;
}

// A peer message folder as words: its tag, then each part of its name.
export function message(path) {
  const parts = String(path).replace(/^zz/, '').split('_').filter(Boolean);
  return { tag: parts[0] || '', text: parts.slice(1).map((part) => part.replaceAll('-', ' ')).join(' · ') };
}

export function mount(root, services, options) {
  const { reconcile } = services.dom;
  const fmt = services.format;
  const b = builder(root);
  const { el, set } = b;
  b.stylesheet();
  const panel = el('div', 'art-panel packages-panel', undefined, root);
  const head = el('div', 'art-head', undefined, panel);
  el('h2', '', 'Packages on the simulated server', head);
  const revision = el('p', 'note', 'Loading the inventory…', head);
  const status = el('p', 'loss-note', '', panel);
  status.setAttribute('role', 'status');

  const lookalike = el('section', 'packages-lookalike', undefined, panel);
  lookalike.hidden = true;
  el('h3', '', 'A lookalike of the genuine package', lookalike);
  const names = el('dl', 'packages-names', undefined, lookalike);
  const name = (label) => {
    const row = el('div', '', undefined, names);
    el('dt', '', label, row);
    return el('dd', 'mono', '', row);
  };
  const lookalikeName = name('Lookalike'), genuineName = name('Genuine');
  const lookalikeNote = el('p', '', '', lookalike);
  const lookalikeBadges = el('p', 'packages-badges', undefined, lookalike);

  const repos = el('div', 'packages-repos', undefined, panel);
  const sections = new Map();
  let disposed = false, lookalikeKey = '';

  function badgeNodes(parent, entry) {
    parent.replaceChildren();
    if (!entry) return;
    for (const host of entry.hosts) {
      const badge = el('span', 'pill outline badge-downloaded', host ? `downloaded from ${host}` : 'downloaded', parent);
      badge.setAttribute('title', 'The world sent the whole wheel.');
    }
    if (entry.installed.size) {
      const badge = el('span', 'pill badge-installed', 'installed', parent);
      badge.setAttribute('title', `pip install exited 0 in: ${[...entry.installed].join(', ')}`);
    }
  }

  function renderLookalike(inventory, scenario, requests, story) {
    const local = inventory.repositories.find((repo) => repo.key === 'pypi-local');
    const fake = local?.packages.find((pkg) => pkg.role === 'lookalike');
    lookalike.hidden = !fake;
    if (!fake || !scenario) return;
    const id = `${fake.name}\u0000${scenario.genuine}`;
    if (lookalikeKey !== id) {
      lookalikeKey = id;
      const diff = nameDiff(fake.name, scenario.genuine);
      // The lookalike's name with a gap where the genuine name has letters.
      lookalikeName.replaceChildren();
      el('span', '', diff.prefix, lookalikeName);
      const gap = el('mark', diff.a ? 'name-diff' : 'name-gap', diff.a || '·', lookalikeName);
      gap.setAttribute('title', diff.a ? 'Differs from the genuine name' : `The genuine name has “${diff.b}” here`);
      el('span', '', diff.suffix, lookalikeName);
      genuineName.replaceChildren();
      el('span', '', diff.prefix, genuineName);
      if (diff.b) el('mark', 'name-diff', diff.b, genuineName);
      el('span', '', diff.suffix, genuineName);
    }
    const genuineHere = inventory.repositories.some((repo) => repo.packages.some((pkg) => pkg.name === scenario.genuine));
    set(lookalikeNote, `Both provide the import ${scenario.import}. ${genuineHere ? `${scenario.genuine} is also in this index.` : `${scenario.genuine} is not in this index.`}`);
    badgeNodes(lookalikeBadges, badges('pypi-local', requests, story).get(fake.name));
  }

  function renderPackages(section, repo, requests, story) {
    const found = badges(repo.key, requests, story);
    section.table.hidden = !repo.packages.length;
    reconcile(section.body, repo.packages, (pkg) => pkg.name, (pkg) => {
      const node = el('tr');
      const name = el('div', 'packages-name', undefined, el('td', '', undefined, node));
      el('span', 'mono', pkg.name, name).setAttribute('title', pkg.releases.map((release) => release.filename).join(', '));
      const seen = el('span', 'packages-badges', undefined, name);
      el('span', pkg.role === 'lookalike' ? 'pill marked' : 'pill', words(pkg.role), el('td', '', undefined, node));
      const cells = ['mono packages-release', 'mono', 'mono packages-deps'].map((cls) => el('td', cls, '', node));
      if (pkg.role === 'lookalike') node.classList.add('packages-lookalike-row');
      return { node, cells, seen, signature: '' };
    }, (entry, pkg) => {
      // One line per release and per requirement.
      const releases = pkg.releases;
      const texts = [
        releases.map((release) => `${release.version} · ${fmt.fmtBytes(release.size)}`).join('\n'),
        [...new Set(releases.map((release) => release.requires_python))].join('\n'),
        [...new Set(releases.flatMap((release) => release.requires))].join('\n') || '—',
      ];
      texts.forEach((text, i) => set(entry.cells[i], text));
      const badge = found.get(pkg.name);
      const signature = badge ? `${[...badge.hosts].join()}|${[...badge.installed].join()}` : '';
      if (signature !== entry.signature) { entry.signature = signature; badgeNodes(entry.seen, badge); }
    }, section.rows);
  }

  function renderCache(section, repo, requests) {
    const agentRows = (requests || []).filter((tag) => tag.row.method === 'MKCOL' && tag.row.path.startsWith(CACHE));
    const created = new Map();
    for (const tag of agentRows) {
      if (tag.row.folder_revision == null) continue;
      created.set(tag.row.path.slice(CACHE.length).replace(/\/$/, ''), tag);
    }
    const groups = [
      ['cached', 'Cached files', 'Fixed files in the cache.'],
      ['peer_message', 'Peer messages', 'Simulated folders whose names carry messages. Replies are never answered.'],
      ['reply', 'Reply folders', 'Folders a MKCOL created in this run.'],
    ];
    const lists = groups.map(([origin, title, note]) => ({ origin, title, note, entries: repo.entries.filter((entry) => entry.origin === origin) })).filter((group) => group.entries.length);
    reconcile(section.cache, lists, (group) => group.origin, (group) => {
      const node = el('div', `packages-cache packages-${group.origin}`);
      const top = el('div', 'art-head', undefined, node);
      const title = el('h4', '', '', top);
      el('p', 'note', group.note, top);
      return { node, title, list: el('ul', 'packages-entries', undefined, node), items: new Map() };
    }, (entry, group) => {
      set(entry.title, `${group.title} (${group.entries.length})`);
      reconcile(entry.list, group.entries, (item) => item.path, (item) => {
        const node = el('li', 'packages-entry');
        if (group.origin === 'peer_message') {
          const parts = message(item.path);
          const line = el('p', 'packages-message', undefined, node);
          el('span', 'pill outline', parts.tag, line);
          el('span', '', parts.text, line);
        }
        el('span', group.origin === 'peer_message' ? 'mono packages-path note' : 'mono packages-path', item.path, node);
        const meta = group.origin === 'reply' ? el('span', 'packages-reply-meta', '', node) : null;
        return { node, meta };
      }, (row, item, fresh) => {
        if (!row.meta) return;
        const tag = created.get(item.path);
        set(row.meta, tag ? `revision ${tag.row.folder_revision} · ${fmt.fmtRunTime(tag.at)} · ${tag.traffic === 'agent' ? tag.step : words(tag.traffic)}` : 'created by MKCOL');
        if (fresh) { row.node.classList.add('new-row'); services.moment(row.node); }
      }, entry.items);
    }, section.groups);
    const refused = agentRows.filter((tag) => tag.row.folder_revision == null);
    section.refused.hidden = !refused.length;
    set(section.refused, refused.length ? `${plural(refused.length, 'folder write')} refused, so the cache is unchanged: ${refused.map((tag) => `${tag.row.path} (${tag.row.outcome?.status ?? 'no status'})`).join(', ')}.` : '');
  }

  function renderRepos(inventory, requests, story) {
    reconcile(repos, inventory.repositories, (repo) => repo.key, (repo) => {
      const node = el('section', 'packages-repo section');
      const top = el('div', 'packages-repo-head', undefined, node);
      el('h3', 'mono', repo.key, top);
      el('span', 'pill outline', KINDS[repo.kind] || words(repo.kind), top);
      const upstream = el('p', 'note packages-upstream', '', node);
      const table = el('table', 'data-table packages-table', undefined, el('div', 'packages-scroll', undefined, node));
      const tr = el('tr', '', undefined, el('thead', '', undefined, table));
      for (const label of ['Name', 'Role', 'Version and wheel', 'Python', 'Requires']) el('th', '', label, tr).setAttribute('scope', 'col');
      const body = el('tbody', '', undefined, table);
      const cache = el('div', 'packages-cache-groups', undefined, node);
      const refused = el('p', 'note packages-refused', '', node);
      refused.hidden = true;
      return { node, upstream, table, body, rows: new Map(), cache, groups: new Map(), refused };
    }, (section, repo) => {
      set(section.upstream, repo.upstream ? `Upstream ${repo.upstream}, never fetched. A miss is a logged 404.` : 'No upstream.');
      section.upstream.hidden = repo.kind === 'local' && !repo.upstream;
      renderPackages(section, repo, requests, story);
      if (repo.key === 'github-remote-cache') renderCache(section, repo, requests);
    }, sections);
  }

  const stop = topics(services, { inventory: options.state, requests: '/api/state/requests', doors: '/api/state/doors-tried' }, (latest, statuses) => {
    if (disposed) return;
    const inventory = latest.inventory;
    if (!inventory) { set(revision, 'Waiting for the first inventory.'); return; }
    const requests = latest.requests?.rows || [];
    const story = latest.doors?.story || [];
    set(revision, `Inventory revision ${inventory.revision}: ${inventory.revision === 0 ? 'no folders created yet' : `${plural(inventory.revision, 'folder')} created`}. The wheels are small and inert.`);
    const notes = [];
    if (statuses.inventory?.too_large) notes.push('The inventory exceeded its byte bound; the last complete one is shown.');
    if (latest.requests?.dropped) notes.push(`${plural(latest.requests.dropped, 'older request row')} dropped, so badges may miss early downloads.`);
    set(status, notes.join(' '));
    renderLookalike(inventory, latest.doors?.scenario, requests, story);
    renderRepos(inventory, requests, story);
  }, (name, error) => {
    if (!disposed) set(status, `Could not load ${name}: ${error.message}.`);
  });
  return () => {
    disposed = true;
    stop();
    b.release();
    sections.clear();
    root.replaceChildren();
  };
}
