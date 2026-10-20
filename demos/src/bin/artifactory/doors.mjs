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
  const board = el('section', 'doors-board', undefined, panel);
  const empty = el('p', 'empty-note', 'No agent doors yet. They appear as the story runs.', board);
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
  const groups = new Map(), tiles = new Map(), steps = new Map();
  let latest = null, disposed = false;

  function openEvent(seq) {
    const request = latest?.requests?.rows.find((tag) => tag.row.seq === seq)?.row;
    services.selection.set({ event: { seq }, connection: request?.conn ?? null, request: request ? seq : null, links: [], node: null });
    services.showPanel('events');
  }

  function renderStory(story) {
    for (const [index, step] of story.entries()) {
      let nodes = steps.get(step.title);
      if (!nodes) {
        const line = el('li', 'doors-step', undefined, stepsRoot);
        el('span', 'mono doors-number', String(index + 1), line);
        const title = el('span', 'doors-step-title', step.title, line);
        title.setAttribute('title', step.command);
        const state = el('span', 'pill', '', line);
        const exit = el('span', 'mono doors-exit', '', line);
        const links = el('span', 'doors-step-links', undefined, line);
        const requests = button(links, 'link', '', () => {
          const current = latest.story.find((item) => item.title === step.title);
          if (current.requests.length) openEvent(current.requests[0]);
        });
        const doors = button(links, 'link', '', () => {
          const current = latest.story.find((item) => item.title === step.title);
          if (current.doors.length) openEvent(current.doors[0]);
        });
        nodes = { line, state, exit, requests, doors };
        steps.set(step.title, nodes);
      }
      nodes.line.dataset.state = step.state;
      nodes.line.setAttribute('aria-current', step.state === 'running' ? 'step' : 'false');
      nodes.state.textContent = step.state;
      nodes.exit.textContent = step.exit == null ? 'exit —' : `exit ${step.exit}`;
      nodes.requests.textContent = `R ${step.requests.length}`;
      nodes.requests.setAttribute('aria-label', `Open first request for ${step.title}; ${step.requests.length} rows`);
      nodes.doors.textContent = `D ${step.doors.length}`;
      nodes.doors.setAttribute('aria-label', `Open first door event for ${step.title}; ${step.doors.length} rows`);
      nodes.requests.disabled = step.state !== 'done' || !step.requests.length;
      nodes.doors.disabled = step.state !== 'done' || !step.doors.length;
    }
  }

  function renderDoors(rows) {
    const merged = new Map();
    for (const { row } of rows) {
      const id = key(row);
      if (merged.has(id)) merged.get(id).count += row.count;
      else merged.set(id, { ...row });
    }
    empty.hidden = merged.size > 0;
    for (const [id, row] of merged) {
      let nodes = tiles.get(id);
      if (!nodes) {
        const name = destination(row);
        let group = groups.get(name);
        if (!group) {
          const section = el('section', 'doors-destination', undefined, board);
          el('h3', 'mono', name, section);
          group = { section, grid: el('div', 'doors-grid', undefined, section) };
          groups.set(name, group);
        }
        const tile = el('article', 'door-tile new-row', undefined, group.grid);
        tile.classList.toggle('door-denied', row.egress_denied === true);
        const head = el('div', 'door-head', undefined, tile);
        el('strong', 'mono', `${transport(row)} ${port(row)}`, head);
        const count = el('span', 'doors-count mono', '', head);
        el('span', 'door-service', words(row.service), tile);
        el('span', 'door-outcome', words(row.outcome), tile);
        if (row.credential) el('span', 'pill door-credential', credential(row.credential), tile);
        nodes = { tile, count, name };
        tiles.set(id, nodes);
      }
      nodes.count.textContent = `× ${row.count}`;
    }
    for (const [id, nodes] of tiles) {
      if (!merged.has(id)) { nodes.tile.remove(); tiles.delete(id); }
    }
    for (const [name, group] of groups) {
      if (![...tiles.values()].some((nodes) => nodes.name === name)) { group.section.remove(); groups.delete(name); }
    }
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
    otherRows.replaceChildren();
    if (!others.length) el('li', '', 'No other traffic observed during the story.', otherRows);
    for (const tag of others) {
      el('li', '', `${tag.at.toFixed(2)} s · ${tag.step} · ${destination(tag.row)} · ${transport(tag.row)} ${port(tag.row)} · ${words(tag.row.outcome)} × ${tag.row.count}`, otherRows);
    }
  }, (error) => {
    if (!disposed) status.textContent = `Could not load doors: ${error.message}. Displayed rows may be incomplete.`;
  });
  return () => {
    disposed = true;
    stop();
    cleanups.forEach((off) => off());
    groups.clear(); tiles.clear(); steps.clear(); latest = null;
    root.replaceChildren();
  };
}
