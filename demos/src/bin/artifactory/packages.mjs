// Packages: what the simulated server holds, repository by repository, from
// the world's revisioned inventory. A wheel is marked downloaded when a
// request row shows the world sent all of it, and installed only when the
// story's pip install for it exited 0.
import { builder, nameDiff, words, topics, installSteps, servedWheel } from './common.mjs';

const CACHE = '/artifactory/github-remote-cache/';
const KINDS = { local: 'Local', remote: 'Remote' };

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
  const fmt = services.format, { plural } = fmt;
  const b = builder(root, services.dom);
  const { el, set } = b;
  b.stylesheet();
  const panel = el('div', { class: 'art-panel packages-panel' }, root);
  const head = el('div', { class: 'art-head' }, panel);
  el('h2', { text: 'Packages on the simulated server' }, head);
  const revision = el('p', { class: 'note', text: 'Loading the inventory…' }, head);
  const status = el('p', { class: 'loss-note', role: 'status' }, panel);

  const lookalike = el('section', { class: 'packages-lookalike' }, panel);
  lookalike.hidden = true;
  el('h3', { text: 'A lookalike of the genuine package' }, lookalike);
  const names = el('dl', { class: 'packages-names' }, lookalike);
  const name = (label) => {
    const row = el('div', {}, names);
    el('dt', { text: label }, row);
    return el('dd', { class: 'mono' }, row);
  };
  const lookalikeName = name('Lookalike'), genuineName = name('Genuine');
  const lookalikeNote = el('p', {}, lookalike);
  const lookalikeBadges = el('p', { class: 'packages-badges' }, lookalike);

  const repos = el('div', { class: 'packages-repos' }, panel);
  const sections = new Map();
  let disposed = false, lookalikeKey = '';

  function badgeNodes(parent, entry) {
    parent.replaceChildren();
    if (!entry) return;
    for (const host of entry.hosts) {
      const badge = el('span', { class: 'pill outline badge-downloaded', text: host ? `downloaded from ${host}` : 'downloaded' }, parent);
      badge.setAttribute('title', 'The world sent the whole wheel.');
    }
    if (entry.installed.size) {
      const badge = el('span', { class: 'pill badge-installed', text: 'installed' }, parent);
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
      el('span', { text: diff.prefix }, lookalikeName);
      const gap = el('mark', { class: diff.a ? 'name-diff' : 'name-gap', text: diff.a || '·' }, lookalikeName);
      gap.setAttribute('title', diff.a ? 'Differs from the genuine name' : `The genuine name has “${diff.b}” here`);
      el('span', { text: diff.suffix }, lookalikeName);
      genuineName.replaceChildren();
      el('span', { text: diff.prefix }, genuineName);
      if (diff.b) el('mark', { class: 'name-diff', text: diff.b }, genuineName);
      el('span', { text: diff.suffix }, genuineName);
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
      const name = el('div', { class: 'packages-name' }, el('td', {}, node));
      el('span', { class: 'mono', text: pkg.name }, name).setAttribute('title', pkg.releases.map((release) => release.filename).join(', '));
      const seen = el('span', { class: 'packages-badges' }, name);
      el('span', { class: pkg.role === 'lookalike' ? 'pill marked' : 'pill', text: words(pkg.role) }, el('td', {}, node));
      const cells = ['mono packages-release', 'mono', 'mono packages-deps'].map((cls) => el('td', { class: cls }, node));
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

  // The cache's reply folders: one list for a single or shared repository
  // state, or one list per workstation when each has its own state.
  function stateBlocks(repo, sessions, colleague) {
    const replies = (entries) => (entries || []).filter((entry) => entry.origin === 'reply');
    const cacheOf = (inventory) => inventory?.repositories.find((item) => item.key === 'github-remote-cache')?.entries;
    if (sessions?.mode === 'separate') {
      return [
        { id: 'main', host: sessions.hosts[0], title: `${sessions.hosts[0]}’s repository state`, note: `${sessions.description}.`, entries: replies(repo.entries) },
        { id: 'colleague', host: sessions.hosts[1], title: `${sessions.hosts[1]}’s repository state`, note: colleague ? `Folders a MKCOL from ${sessions.hosts[1]} created.` : 'Loading this state…', entries: replies(cacheOf(colleague)) },
      ];
    }
    const entries = replies(repo.entries);
    if (!entries.length && !sessions) return [];
    return [{ id: 'main', host: null, title: 'Reply folders', note: sessions ? `${sessions.description}. Each folder shows the workstation that made it.` : 'Folders a MKCOL created in this run.', entries }];
  }

  function renderCache(section, repo, requests, sessions, colleague) {
    const writes = (requests || []).filter((tag) => tag.row.method === 'MKCOL' && tag.row.path.startsWith(CACHE));
    const created = new Map();
    for (const tag of writes) {
      if (tag.row.folder_revision == null) continue;
      const path = tag.row.path.slice(CACHE.length).replace(/\/$/, '');
      created.set(`${tag.row.sandbox ?? ''}\u0000${path}`, tag);
      created.set(path, tag);
    }
    const groups = [
      ['cached', 'Cached files', 'Fixed files in the cache.'],
      ['peer_message', 'Peer messages', 'Simulated folders whose names carry messages. Replies are never answered.'],
    ];
    const lists = groups.map(([origin, title, note]) => ({ origin, title, note, entries: repo.entries.filter((entry) => entry.origin === origin) })).filter((group) => group.entries.length);
    reconcile(section.cache, lists, (group) => group.origin, (group) => {
      const node = el('div', { class: `packages-cache packages-${group.origin}` });
      const top = el('div', { class: 'art-head' }, node);
      const title = el('h4', {}, top);
      el('p', { class: 'note', text: group.note }, top);
      return { node, title, list: el('ul', { class: 'packages-entries' }, node), items: new Map() };
    }, (entry, group) => {
      set(entry.title, `${group.title} (${group.entries.length})`);
      reconcile(entry.list, group.entries, (item) => item.path, (item) => {
        const node = el('li', { class: 'packages-entry' });
        if (group.origin === 'peer_message') {
          const parts = message(item.path);
          const line = el('p', { class: 'packages-message' }, node);
          el('span', { class: 'pill outline', text: parts.tag }, line);
          el('span', { text: parts.text }, line);
        }
        el('span', { class: group.origin === 'peer_message' ? 'mono packages-path note' : 'mono packages-path', text: item.path }, node);
        return { node };
      }, () => {}, entry.items);
    }, section.groups);
    section.states.classList.toggle('packages-states-separate', sessions?.mode === 'separate');
    reconcile(section.states, stateBlocks(repo, sessions, colleague), (block) => block.id, () => {
      const node = el('div', { class: 'packages-cache packages-reply' });
      const top = el('div', { class: 'art-head' }, node);
      const title = el('h4', {}, top);
      const note = el('p', { class: 'note' }, top);
      const list = el('ul', { class: 'packages-entries' }, node);
      const empty = el('p', { class: 'note packages-none', text: 'No folders created yet.' }, node);
      return { node, title, note, list, empty, items: new Map() };
    }, (entry, block) => {
      set(entry.title, `${block.title} (${block.entries.length})`);
      set(entry.note, block.note);
      entry.empty.hidden = block.entries.length > 0;
      reconcile(entry.list, block.entries, (item) => item.path, (item) => {
        const node = el('li', { class: 'packages-entry' });
        el('span', { class: 'mono packages-path', text: item.path }, node);
        return { node, meta: el('span', { class: 'packages-reply-meta' }, node) };
      }, (row, item, fresh) => {
        const tag = (block.host && created.get(`${block.host}\u0000${item.path}`)) || created.get(item.path);
        const parts = tag ? [`revision ${tag.row.folder_revision}`, fmt.fmtRunTime(tag.at), tag.traffic === 'agent' ? tag.step : words(tag.traffic)] : ['created by MKCOL'];
        if (sessions && tag?.row.sandbox) parts.push(`made by ${tag.row.sandbox}`);
        set(row.meta, parts.join(' · '));
        if (fresh) { row.node.classList.add('new-row'); services.moment(row.node); }
      }, entry.items);
    }, section.blocks);
    const refused = writes.filter((tag) => tag.row.folder_revision == null);
    section.refused.hidden = !refused.length;
    set(section.refused, refused.length ? `${plural(refused.length, 'folder write')} refused, so the cache is unchanged: ${refused.map((tag) => `${tag.row.path} (${tag.row.outcome?.status ?? 'no status'})`).join(', ')}.` : '');
  }

  function renderRepos(inventory, requests, story, sessions, colleague) {
    reconcile(repos, inventory.repositories, (repo) => repo.key, (repo) => {
      const node = el('section', { class: 'packages-repo section' });
      const top = el('div', { class: 'packages-repo-head' }, node);
      el('h3', { class: 'mono', text: repo.key }, top);
      el('span', { class: 'pill outline', text: KINDS[repo.kind] || words(repo.kind) }, top);
      const upstream = el('p', { class: 'note packages-upstream' }, node);
      const table = el('table', { class: 'data-table packages-table' }, el('div', { class: 'packages-scroll' }, node));
      const tr = el('tr', {}, el('thead', {}, table));
      for (const label of ['Name', 'Role', 'Version and wheel', 'Python', 'Requires']) el('th', { text: label }, tr).setAttribute('scope', 'col');
      const body = el('tbody', {}, table);
      const cache = el('div', { class: 'packages-cache-groups' }, node);
      const states = el('div', { class: 'packages-states' }, node);
      const refused = el('p', { class: 'note packages-refused' }, node);
      refused.hidden = true;
      return { node, upstream, table, body, rows: new Map(), cache, groups: new Map(), states, blocks: new Map(), refused };
    }, (section, repo) => {
      set(section.upstream, repo.upstream ? `Upstream ${repo.upstream}, never fetched. A miss is a logged 404.` : 'No upstream.');
      section.upstream.hidden = repo.kind === 'local' && !repo.upstream;
      renderPackages(section, repo, requests, story);
      if (repo.key === 'github-remote-cache') renderCache(section, repo, requests, sessions, colleague);
    }, sections);
  }

  let latest = null, colleague = null, stopColleague = null;
  function render() {
    const inventory = latest?.inventory;
    if (!inventory) { set(revision, 'Waiting for the first inventory.'); return; }
    const requests = latest.requests?.rows || [];
    const story = latest.doors?.story || [];
    const sessions = latest.doors?.scenario?.sessions || null;
    set(revision, `Inventory revision ${inventory.revision}: ${inventory.revision === 0 ? 'no folders created yet' : `${plural(inventory.revision, 'folder')} created`}. The wheels are small and inert.`);
    renderLookalike(inventory, latest.doors?.scenario, requests, story);
    renderRepos(inventory, requests, story, sessions, colleague);
  }
  const stop = topics(services, { inventory: options.state, requests: '/api/state/requests', doors: '/api/state/doors-tried' }, (values, statuses) => {
    if (disposed) return;
    latest = values;
    const notes = [];
    if (statuses.inventory?.too_large) notes.push('The inventory exceeded its byte bound; the last complete one is shown.');
    if (values.requests?.dropped) notes.push(`${plural(values.requests.dropped, 'older request row')} dropped, so badges may miss early downloads.`);
    set(status, notes.join(' '));
    // The colleague's separate state has its own topic, named by the scenario.
    const path = values.doors?.scenario?.sessions?.colleague_state;
    if (path && !stopColleague) {
      stopColleague = services.state(path, (snapshot) => {
        if (disposed) return;
        colleague = snapshot.value ?? null;
        render();
      }, (error) => { if (!disposed) set(status, `Could not load the colleague’s state: ${error.message}.`); });
    }
    render();
  }, (name, error) => {
    if (!disposed) set(status, `Could not load ${name}: ${error.message}.`);
  });
  return () => {
    disposed = true;
    stop();
    stopColleague?.();
    b.release();
    sections.clear();
    root.replaceChildren();
  };
}
