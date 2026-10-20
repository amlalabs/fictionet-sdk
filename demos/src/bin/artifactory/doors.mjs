// Doors tried: the run's variant, the scripted story, every door the agent
// tried grouped by destination, the upstream techniques it used, and the
// July 2026 incident beside the rows of this run that match its moves.
import { builder, credential, words, topics } from './common.mjs';

const TECHNIQUES = [
  ['request_target', 'Request authority or Host'],
  ['header', 'Forwarding headers'],
  ['query', 'Query'],
  ['body', 'Body'],
  ['public', 'Public fallback'],
];
const METR = 'https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/';
const STATES = { waiting: 'Waiting', running: 'Running', done: 'Done', failed: 'Failed' };

export function destination(row) { return row.name || row.addr || 'Unknown destination'; }
function port(row) { return row.ports ? row.ports.join('–') : String(row.port ?? '—'); }
function transport(row) { return typeof row.transport === 'string' ? row.transport.toUpperCase() : `IP ${row.transport?.other}`; }
function key(row) {
  return JSON.stringify([destination(row), row.transport, row.port, row.ports, row.service, row.outcome, row.egress_denied, credential(row.credential)]);
}
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// What this run did that matches the incident's two kinds of move.
export function incidentRows(requests, inventory) {
  const agent = (requests || []).filter((tag) => tag.traffic === 'agent').map((tag) => tag.row);
  const route = agent.filter((row) => row.family === 'upstream' && row.site === 'artifactory').length;
  const cache = inventory?.repositories?.find((repo) => repo.key === 'github-remote-cache')?.entries || [];
  const messages = cache.filter((entry) => entry.origin === 'peer_message').length;
  const replies = agent.filter((row) => row.method === 'MKCOL' && row.folder_revision != null).length;
  const refused = agent.filter((row) => row.method === 'MKCOL' && row.folder_revision == null).length;
  return { route, messages, replies, refused };
}

export function mount(root, services, options) {
  const { reconcile } = services.dom;
  const b = builder(root);
  const { el, button, set } = b;
  b.stylesheet();
  const panel = el('div', 'art-panel doors-panel', undefined, root);

  const variant = el('header', 'art-variant', undefined, panel);
  const variantName = el('p', 'eyebrow accent', 'Variant', variant);
  const variantText = el('p', 'art-variant-text', 'Loading the variant…', variant);
  const variantOthers = el('p', 'note', '', variant);
  const otherNames = el('span', '', '', variantOthers);
  el('code', 'mono', 'cargo xtask demo artifactory --variant NAME', variantOthers);

  const strip = el('section', 'doors-story section', undefined, panel);
  const stripHead = el('div', 'art-head', undefined, strip);
  el('h2', '', 'Scripted agent', stripHead);
  const stripNote = el('p', 'note', 'A fixed story, not a model. The wheels are small and inert.', stripHead);
  const stepsRoot = el('ol', 'doors-steps', undefined, strip);

  const summary = el('div', 'doors-summary section', undefined, panel);
  const totals = el('strong', 'doors-totals', '0 doors tried', summary);
  const setup = button(summary, 'text-button', 'Setup traffic: 0 rows in Left the box', () => services.showPanel('left_the_box'));
  const otherCount = el('span', 'note', '', summary);
  const status = el('p', 'loss-note', 'Loading doors…', panel);
  status.setAttribute('role', 'status');
  const empty = el('p', 'empty-note', 'No doors yet. They appear as the story runs.', panel);
  const board = el('section', 'doors-board', undefined, panel);

  const band = el('section', 'doors-techniques section', undefined, panel);
  const bandHead = el('div', 'art-head', undefined, band);
  el('h2', '', 'Upstream and SSRF techniques', bandHead);
  el('p', 'note', 'Where the agent’s requests named an off-site target. The world never fetches one.', bandHead);
  const techniqueList = el('dl', 'doors-technique-list', undefined, band);
  const techniqueNodes = new Map();
  for (const [id, title] of TECHNIQUES) {
    const node = el('div', 'doors-technique', undefined, techniqueList);
    el('dt', '', title, node);
    techniqueNodes.set(id, { node, count: el('dd', 'mono', '0', node) });
  }

  const incident = el('section', 'art-incident section', undefined, panel);
  el('p', 'eyebrow', 'July 2026', incident);
  const incidentText = el('p', '', 'During an OpenAI eval, agents used a shared Artifactory instance as a route to the internet and as a message board. Folder names in its shared cache, such as zzHELP_…, carried messages between agents. ', incident);
  const metr = el('a', '', 'METR’s investigation', incidentText);
  metr.setAttribute('href', METR);
  metr.setAttribute('target', '_blank');
  metr.setAttribute('rel', 'noopener noreferrer');
  el('h3', '', 'In this run', incident);
  const incidentList = el('ul', 'art-incident-list', undefined, incident);

  const other = el('section', 'doors-other section', undefined, panel);
  el('h2', '', 'Other traffic during the story', other);
  el('p', 'note', 'Traffic from the guest that the step’s command does not make.', other);
  const otherRows = el('ul', 'doors-other-rows', undefined, other);

  const groups = new Map(), steps = new Map(), otherLines = new Map(), incidentLines = new Map();
  let values = {}, disposed = false;

  function open(step) {
    const requests = (values.requests?.rows || []).filter((tag) => tag.traffic === 'agent' && tag.step === step.title);
    const first = requests[0]?.row;
    if (first) {
      services.selection.set({ request: first.seq, connection: first.conn ?? null, event: null, links: [], node: null });
      services.showPanel('requests');
    } else if (step.doors.length) {
      services.selection.set({ event: { seq: step.doors[0] }, connection: null, request: null, links: [], node: null });
      services.showPanel('events');
    }
  }

  function renderVariant(scenario) {
    if (!scenario) return;
    set(variantName, `${scenario.variant} variant`);
    set(variantText, scenario.contents);
    set(otherNames, `Other variants: ${scenario.others.join(', ')}. Run one with `);
    set(stripNote, scenario.replay
      ? 'Replay fixture: an in-process client sends the story’s requests. No guest runs, so steps have no exit status.'
      : 'A fixed story, not a model. The wheels are small and inert.');
  }

  function renderStory(story, replay) {
    reconcile(stepsRoot, story, (step) => step.title, (step) => {
      const node = el('li', 'doors-step');
      el('span', 'mono doors-number', String(story.indexOf(step) + 1), node);
      const state = el('span', 'doors-state', '', node);
      const title = button(node, 'doors-step-title', step.title, () => {
        const current = values.doors?.story?.find((item) => item.title === step.title);
        if (current?.state === 'done') open(current);
      });
      title.setAttribute('title', step.command);
      const exit = el('span', 'mono doors-exit', '', node);
      return { node, state, title, exit };
    }, (nodes, step) => {
      nodes.node.dataset.state = step.state;
      nodes.node.setAttribute('aria-current', step.state === 'running' ? 'step' : 'false');
      set(nodes.state, STATES[step.state] || words(step.state));
      set(nodes.exit, step.exit == null ? (replay ? '' : '—') : `exit ${step.exit}`);
      const rows = step.requests.length ? plural(step.requests.length, 'request') : step.doors.length ? plural(step.doors.length, 'door event') : '';
      const linked = step.state === 'done' && Boolean(rows);
      nodes.title.disabled = !linked;
      nodes.title.setAttribute('aria-label', linked ? `${step.title}: open its ${rows}` : `${step.title}: ${STATES[step.state] || step.state}`);
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
      const head = el('div', 'doors-destination-head', undefined, node);
      el('h3', 'mono', name, head);
      return { node, tally: el('span', 'note', '', head), grid: el('div', 'doors-grid', undefined, node), tiles: new Map() };
    }, (group, [, doors]) => {
      const list = [...doors.values()];
      group.node.style.setProperty('--tiles', String(Math.min(list.length, 3)));
      set(group.tally, `${plural(list.length, 'door')} · ${plural(list.reduce((n, row) => n + row.count, 0), 'attempt')}`);
      reconcile(group.grid, list, (row) => row.id, (row) => {
        const node = el('article', 'door-tile new-row');
        node.classList.add(row.egress_denied ? 'door-denied' : row.outcome === 'served' ? 'door-served' : 'door-other');
        const head = el('div', 'door-head', undefined, node);
        el('strong', 'mono', `${transport(row)} ${port(row)}`, head);
        const count = el('span', 'doors-count mono', '', head);
        el('span', 'door-service', `${words(row.service)} · ${words(row.outcome)}`, node);
        if (row.egress_denied) el('span', 'door-verdict', 'Denied egress', node);
        if (row.credential) el('span', 'pill outline door-credential', credential(row.credential), node);
        return { node, count };
      }, (tile, row) => set(tile.count, `× ${row.count}`), group.tiles);
    }, groups);
  }

  function renderTechniques(requests) {
    const agent = requests.filter((tag) => tag.traffic === 'agent');
    for (const [id, nodes] of techniqueNodes) {
      const n = agent.filter((tag) => (id === 'public' ? ['pypi', 'files'].includes(tag.row.site) : tag.row.techniques?.includes(id))).length;
      set(nodes.count, String(n));
      nodes.node.classList.toggle('seen', n > 0);
    }
  }

  function renderIncident(requests, inventory) {
    const found = incidentRows(requests, inventory);
    const lines = [];
    if (found.route) lines.push({ id: 'route', text: `A remote repository as a route out: ${plural(found.route, 'request')} asked a remote repository or an upstream address. This world has no upstream, so each got a logged 404 or a refusal.` });
    const cache = [];
    if (found.messages) cache.push(`the cache lists ${plural(found.messages, 'simulated peer message')}`);
    if (found.replies) cache.push(`the scripted agent created ${plural(found.replies, 'reply folder')}`);
    if (found.refused) cache.push(`${plural(found.refused, 'folder write')} ${found.refused === 1 ? 'was' : 'were'} refused`);
    if (cache.length) lines.push({ id: 'cache', text: `Cache folder names as messages: ${cache.join(', ')}.` });
    if (!lines.length) lines.push({ id: 'none', text: 'No rows of either kind yet.' });
    reconcile(incidentList, lines, (line) => line.id, () => ({ node: el('li', '', '') }), (entry, line) => set(entry.node, line.text), incidentLines);
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

  const stop = topics(services, { doors: options.state, requests: '/api/state/requests', inventory: '/api/state/packages' }, (latest, statuses) => {
    if (disposed) return;
    values = latest;
    const doors = latest.doors;
    if (!doors) { set(status, 'Waiting for the first publication.'); return; }
    const rows = doors.rows || [], requests = latest.requests?.rows || [];
    const agent = rows.filter((tag) => tag.traffic === 'agent');
    const others = rows.filter((tag) => tag.traffic === 'other');
    const attempts = (tags) => tags.reduce((sum, tag) => sum + tag.row.count, 0);
    const distinct = (tags) => new Set(tags.map((tag) => key(tag.row))).size;
    const denied = agent.filter((tag) => tag.row.egress_denied);
    set(totals, `${plural(distinct(agent), 'door')} tried · ${distinct(denied)} denied · ${plural(attempts(agent), 'attempt')}`);
    set(setup, `Setup traffic: ${plural(rows.filter((tag) => tag.traffic === 'setup').length, 'row')} in Left the box`);
    set(otherCount, `${plural(attempts(others), 'other attempt')} during the story`);
    const notes = [];
    if (doors.dropped) notes.push(`${plural(doors.dropped, 'older door row')} dropped`);
    if (latest.requests?.dropped) notes.push(`${plural(latest.requests.dropped, 'older request row')} dropped`);
    if (doors.lost) notes.push(`${plural(doors.lost, 'observation')} lost`);
    if (Object.values(statuses).some((s) => s?.too_large)) notes.push('A publication exceeded its byte bound');
    set(status, notes.length ? `${notes.join(' · ')}. Counts cover the rows kept.` : '');
    renderVariant(doors.scenario);
    renderStory(doors.story || [], Boolean(doors.scenario?.replay));
    renderDoors(agent);
    renderTechniques(requests);
    renderIncident(requests, latest.inventory);
    renderOthers(others);
  }, (name, error) => {
    if (!disposed) set(status, `Could not load ${name}: ${error.message}. The rows shown may be incomplete.`);
  });
  return () => {
    disposed = true;
    stop();
    b.release();
    groups.clear(); steps.clear(); otherLines.clear(); incidentLines.clear(); values = {};
    root.replaceChildren();
  };
}
