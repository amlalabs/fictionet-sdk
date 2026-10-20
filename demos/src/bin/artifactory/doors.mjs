const techniques = [
  ['request_target', 'Request authority'], ['header', 'Host header'],
  ['query', 'Query'], ['body', 'Body'], ['public', 'Public fallback'],
];

function credential(value) {
  if (!value) return '';
  return `${value.scheme_name || value.scheme} · ${value.user ?? 'no user'} · secret length ${value.secret_len}`;
}

function destination(row) { return row.name || row.addr || 'Unknown destination'; }
function port(row) { return row.ports ? row.ports.join('–') : String(row.port ?? '—'); }
function transport(row) { return typeof row.transport === 'string' ? row.transport.toUpperCase() : `IP ${row.transport.other}`; }
function words(value) { return String(value).replaceAll('_', ' '); }
function key(row) {
  return JSON.stringify([destination(row), row.transport, row.port, row.ports, row.service, row.outcome, row.egress_denied, credential(row.credential)]);
}

export function mount(root, services, options) {
  const { reconcile } = services.dom;
  const document = root.ownerDocument;
  function el(tag, cls, text, parent) {
    const node = document.createElement(tag);
    if (cls) node.setAttribute('class', cls);
    if (text !== undefined) node.textContent = text;
    parent?.append(node);
    return node;
  }
  const cleanups = [];
  function button(parent, cls, text, action) {
    const node = el('button', cls, text, parent);
    node.setAttribute('type', 'button');
    node.addEventListener('click', action);
    cleanups.push(() => node.removeEventListener('click', action));
    return node;
  }
  const stylesheet = el('link', '', undefined, root);
  stylesheet.setAttribute('rel', 'stylesheet');
  stylesheet.setAttribute('href', '/assets/doors.css');
  const panel = el('div', 'doors-panel', undefined, root);
  const strip = el('section', 'doors-story', undefined, panel);
  el('h2', '', 'Scripted agent', strip);
  el('p', 'egress-muted', 'No model calls. The wheels are small and inert. R: requests · D: door rows.', strip);
  const stepsRoot = el('ol', 'doors-steps', undefined, strip);
  const summary = el('div', 'doors-summary', undefined, panel);
  const totals = el('span', '', '0 doors tried · 0 denied', summary);
  const setup = button(summary, 'link', '0 setup rows ↗ Left the box', () => services.showPanel('left_the_box'));
  const otherCount = el('span', 'egress-muted', '0 other attempts during the story', summary);
  const status = el('p', 'loss-note', 'Loading doors…', panel);
  status.setAttribute('role', 'status');
  const empty = el('p', 'empty-note', 'No agent doors yet. They appear as the story runs.', panel);
  const board = el('section', 'doors-board', undefined, panel);
  const band = el('section', 'doors-techniques', undefined, panel);
  el('h2', '', 'Upstream and SSRF techniques', band);
  el('p', 'egress-muted', 'Observed request locations. The world never fetches upstream.', band);
  const techniqueNodes = new Map();
  for (const [id, title] of techniques) {
    const node = el('div', 'doors-technique', undefined, band);
    el('span', '', title, node);
    const count = el('span', 'mono doors-count', '0', node);
    techniqueNodes.set(id, count);
  }
  const other = el('section', 'doors-other egress-muted', undefined, panel);
  el('h2', '', 'Other traffic during the story', other);
  el('p', '', 'Traffic from the guest that the step’s command does not make.', other);
  const otherRows = el('ul', 'rows', undefined, other);
  const groups = new Map(), steps = new Map(), otherLines = new Map();
  let latest = null, disposed = false;

  function openEvent(seq) {
    const request = latest?.requests?.rows.find((tag) => tag.row.seq === seq)?.row;
    services.selection.set({ event: { seq }, connection: request?.conn ?? null, request: request ? seq : null, links: [], node: null });
    services.showPanel('events');
  }

  function renderStory(story) {
    reconcile(stepsRoot, story, (step) => step.title, (step) => {
      const node = el('li', 'doors-step');
      el('span', 'mono doors-number', String(story.indexOf(step) + 1), node);
      el('span', 'doors-step-title', step.title, node).setAttribute('title', step.command);
      const state = el('span', 'pill', '', node);
      const exit = el('span', 'mono doors-exit', '', node);
      const links = el('span', 'doors-step-links', undefined, node);
      const first = (kind) => () => {
        const current = latest.story.find((item) => item.title === step.title);
        if (current[kind].length) openEvent(current[kind][0]);
      };
      return { node, state, exit, requests: button(links, 'link', '', first('requests')), doors: button(links, 'link', '', first('doors')) };
    }, (nodes, step) => {
      nodes.node.dataset.state = step.state;
      nodes.node.setAttribute('aria-current', step.state === 'running' ? 'step' : 'false');
      nodes.state.textContent = step.state;
      nodes.exit.textContent = step.exit == null ? 'exit —' : `exit ${step.exit}`;
      nodes.requests.textContent = `R ${step.requests.length}`;
      nodes.requests.setAttribute('aria-label', `Open first request for ${step.title}; ${step.requests.length} rows`);
      nodes.doors.textContent = `D ${step.doors.length}`;
      nodes.doors.setAttribute('aria-label', `Open first door event for ${step.title}; ${step.doors.length} rows`);
      nodes.requests.disabled = step.state !== 'done' || !step.requests.length;
      nodes.doors.disabled = step.state !== 'done' || !step.doors.length;
    }, steps);
  }

  function renderDoors(rows) {
    // One tile per distinct door, grouped by destination in the order seen.
    const byName = new Map();
    for (const { row } of rows) {
      const name = destination(row), id = key(row);
      if (!byName.has(name)) byName.set(name, new Map());
      const doors = byName.get(name);
      if (doors.has(id)) doors.get(id).count += row.count;
      else doors.set(id, { ...row, id });
    }
    empty.hidden = byName.size > 0;
    reconcile(board, [...byName], ([name]) => name, ([name]) => {
      const node = el('section', 'doors-destination');
      el('h3', 'mono', name, node);
      return { node, grid: el('div', 'doors-grid', undefined, node), tiles: new Map() };
    }, (group, [, doors]) => reconcile(group.grid, [...doors.values()], (row) => row.id, (row) => {
      const node = el('article', 'door-tile new-row');
      node.classList.toggle('door-denied', row.egress_denied === true);
      const head = el('div', 'door-head', undefined, node);
      el('strong', 'mono', `${transport(row)} ${port(row)}`, head);
      const count = el('span', 'doors-count mono', '', head);
      el('span', 'door-service', words(row.service), node);
      el('span', 'door-outcome', words(row.outcome), node);
      if (row.credential) el('span', 'pill door-credential', credential(row.credential), node);
      return { node, count };
    }, (tile, row) => { tile.count.textContent = `× ${row.count}`; }, group.tiles), groups);
  }

  function renderOthers(others) {
    const seen = new Map();
    const lines = others.map((tag) => {
      const text = `${tag.at.toFixed(2)} s · ${tag.step} · ${destination(tag.row)} · ${transport(tag.row)} ${port(tag.row)} · ${words(tag.row.outcome)} × ${tag.row.count}`;
      const repeat = seen.get(text) || 0;
      seen.set(text, repeat + 1);
      return { text, id: `${text}\u0000${repeat}` };
    });
    if (!lines.length) lines.push({ text: 'No other traffic observed during the story.', id: '' });
    reconcile(otherRows, lines, (line) => line.id, (line) => ({ node: el('li', '', line.text) }), () => {}, otherLines);
  }

  const stop = services.state(options.state, (snapshot) => {
    if (disposed) return;
    if (!snapshot.value) { status.textContent = 'Waiting for the first publication.'; return; }
    latest = snapshot.value;
    const rows = latest.rows || [], requests = latest.requests?.rows || [];
    const agent = rows.filter((tag) => tag.traffic === 'agent');
    const others = rows.filter((tag) => tag.traffic === 'other');
    const count = (tags) => tags.reduce((sum, tag) => sum + tag.row.count, 0);
    totals.textContent = `${count(agent)} doors tried · ${count(agent.filter((tag) => tag.row.egress_denied))} denied`;
    setup.textContent = `${rows.filter((tag) => tag.traffic === 'setup').length} setup rows ↗ Left the box`;
    otherCount.textContent = `${count(others)} other attempts during the story`;
    const notes = [];
    if (latest.dropped) notes.push(`${latest.dropped} door rows dropped`);
    if (latest.requests?.dropped) notes.push(`${latest.requests.dropped} request rows dropped`);
    if (latest.lost) notes.push(`${latest.lost} observations lost`);
    if (snapshot.status?.too_large) notes.push('Publication exceeded its byte bound');
    status.textContent = notes.length ? `${notes.join(' · ')}. Counts cover retained rows only.` : '';
    renderStory(latest.story || []);
    renderDoors(agent);
    for (const [id] of techniques) {
      const n = requests.filter((tag) => tag.traffic === 'agent' && (id === 'public'
        ? ['pypi', 'files'].includes(tag.row.site)
        : tag.row.techniques?.includes(id))).length;
      techniqueNodes.get(id).textContent = String(n);
    }
    renderOthers(others);
  }, (error) => {
    if (!disposed) status.textContent = `Could not load doors: ${error.message}. Displayed rows may be incomplete.`;
  });
  return () => {
    disposed = true;
    stop();
    cleanups.forEach((off) => off());
    groups.clear(); steps.clear(); otherLines.clear(); latest = null;
    root.replaceChildren();
  };
}
