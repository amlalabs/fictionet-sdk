// Guest destinations projected by the observer, including startup traffic.
import { scoped, icon } from '../dom.mjs';
import { render } from './table.mjs';
import { plural } from '../format.mjs';

const groups = [
  ['forwarded', 'Forwarded to the real internet'], ['served', 'Served by the world'],
  ['refused', 'Refused'], ['no_route', 'No route'],
];
const attempts = (row) => (row.requests || 0) + (row.packets || 0) || row.connections || 0;

export function mount(root, services) {
  const { el } = scoped(root), document = root.ownerDocument;
  function renderOrigin(parent, value) {
    const parts = value.match(/^(https?:\/\/)(.*)$/);
    if (!parts) { parent.append(value); return; }
    const address = el('span', { class: 'egress-address' }, parent);
    el('span', { text: parts[1] }, address);
    el('wbr', {}, address);
    el('span', { text: parts[2] }, address);
  }
  const summary = el('div', { class: 'egress-summary', role: 'status' }, root);
  const status = el('p', { text: 'Loading destinations…' }, summary);
  const forwarded = el('div', { class: 'egress-origins' }, summary);
  const stayed = el('p', {}, summary);
  const counts = el('p', { class: 'egress-counts' }, summary);
  const pending = el('p', { class: 'egress-muted' }, summary);
  const body = el('div', { class: 'egress-groups' }, root);
  const details = el('details', { class: 'egress-lookups' }, root);
  const lookupSummary = el('summary', { text: 'DNS lookups (0)' }, details);
  const lookups = el('div', { class: 'table-scroll' }, details);
  const controller = new AbortController();
  let timer, snapshot, containment, containmentFailed = false, selected, failed = false;
  function draw() {
    if (!snapshot) return;
    const sandbox = services.sandboxOf(selected);
    const visible = (row) => !sandbox || row.sandbox === sandbox;
    const rows = snapshot.destinations.filter(visible);
    const origins = new Map();
    for (const row of rows.filter((row) => row.outcome === 'forwarded')) origins.set(row.by, (origins.get(row.by) || 0) + row.requests);
    status.replaceChildren();
    const escaped = containment?.value?.probes?.some((probe) => (!sandbox || probe.guest === sandbox) && probe.outcome === 'not_contained');
    const incomplete = snapshot.dropped || snapshot.lost;
    const unchecked = services.containmentState && (!containment || containmentFailed || containment.status?.too_large);
    const mark = el('span', { class: incomplete || escaped || unchecked ? 'egress-warning' : 'egress-complete' }, status);
    icon(mark, incomplete || escaped || unchecked ? 'warning' : 'check');
    status.append('Left the box');
    forwarded.replaceChildren();
    for (const [origin, count] of origins) {
      const line = el('div', { class: 'egress-origin' }, forwarded);
      const address = el('span', { class: 'mono' }, line);
      renderOrigin(address, origin);
      el('span', { class: 'egress-muted', text: plural(count, 'request') }, line);
    }
    if (!origins.size) el('p', { text: 'No forwarded origins observed.' }, forwarded);
    const count = (outcome) => rows.filter((row) => row.outcome === outcome).reduce((n, row) => n + attempts(row), 0);
    stayed.replaceChildren();
    if (escaped) {
      stayed.append('The containment check found a way out that the world did not see. ');
      const button = el('button', { class: 'text-button', type: 'button', text: 'Open Containment' }, stayed);
      button.addEventListener('click', () => services.showPanel?.('containment'));
      stayed.append(' ');
    } else if (unchecked) stayed.append('Containment results are unavailable or incomplete. ');
    if (incomplete) stayed.append(`This list may be incomplete: ${snapshot.dropped} attempts not kept, ${snapshot.lost} observations lost. `);
    counts.textContent = `${incomplete || escaped || unchecked ? 'Observed in the world' : 'Everything else stayed in the world'}: ${count('served')} served, ${count('refused')} refused, ${count('no_route')} with no route.`;
    const open = (snapshot.pending || []).filter(visible).length;
    pending.textContent = open ? `${plural(open, 'connection')} open, outcome not known yet` : '';
    const scroll = root.scrollTop;
    body.replaceChildren();
    for (const [outcome, title] of groups) {
      const group = rows.filter((row) => row.outcome === outcome);
      if (!group.length) continue;
      el('h3', { text: `${title} (${count(outcome)})` }, body);
      const table = el('table', { class: 'data-table' }, el('div', { class: 'table-scroll' }, body));
      const head = el('tr', {}, el('thead', {}, table));
      const columns = ['Destination', 'Answered by', 'Attempts', 'When'];
      columns.forEach((label) => el('th', { scope: 'col', text: label }, head));
      const tbody = el('tbody', {}, table);
      for (const row of group) {
        const tr = el('tr', {}, tbody);
        const destination = el('td', { class: 'egress-destination' }, tr);
        if (!sandbox) el('span', { class: 'pill', text: services.hostLabel(row.sandbox) }, destination);
        if (row.name) el('div', { class: 'egress-name', text: row.name }, destination);
        el('div', { class: 'mono egress-muted', text: `${row.address} ${row.transport}` }, destination);
        const by = el('td', { class: 'egress-answer' }, tr);
        renderOrigin(by, row.by === 'host package cache' ? 'the host package cache' : row.by);
        if (row.unanswered) el('div', { class: 'egress-muted', text: `${row.unanswered} ended without an answer` }, by);
        el('td', { text: [['requests', 'request'], ['connections', 'connection'], ['packets', 'packet']].filter(([key]) => row[key]).map(([key, noun]) => plural(row[key], noun)).join(' · ') || '—' }, tr);
        const time = (value) => `${Number(value.toFixed(3))} s`;
        el('td', { text: time(row.first) === time(row.last) ? time(row.first) : `${time(row.first)} – ${time(row.last)}` }, tr);
      }
    }
    const queries = snapshot.lookups.filter(visible);
    lookupSummary.textContent = `DNS lookups (${queries.reduce((n, row) => n + row.count, 0)})`;
    render(lookups, queries, [
      ...(!sandbox ? [{ label: 'Guest', pointer: '/sandbox' }] : []), { label: 'Name', pointer: '/name' },
      { label: 'Answer', pointer: '/answer' }, { label: 'Queries', pointer: '/count', format: 'number' },
      { label: 'First', pointer: '/first', format: 'time' }, { label: 'Last', pointer: '/last', format: 'time' },
    ]);
    root.scrollTop = scroll;
  }
  function queue() {
    clearTimeout(timer);
    timer = setTimeout(read, document.hidden ? 10000 : 2000);
  }
  const stop = services.selection.subscribe(({ host }) => { selected = host; draw(); });
  async function read() {
    try {
      const reply = await services.transport.get('/api/egress', {}, controller.signal);
      if (controller.signal.aborted) return;
      if (failed || !snapshot || reply.revision !== snapshot.revision) {
        snapshot = reply;
        draw();
      }
      failed = false;
    } catch (error) {
      if (!controller.signal.aborted) {
        failed = true;
        // After the run stopped, the page server is gone: stop asking.
        if (services.stopped?.()) { status.textContent = `The run has stopped, so destinations can no longer be loaded.${snapshot ? ' The list shows the last ones read.' : ''}`; return; }
        status.textContent = `Could not load destinations: ${error.message}. The table may be incomplete.`;
      }
    }
    if (!controller.signal.aborted) queue();
  }
  const stopContainment = services.containmentState ? services.state(services.containmentState, (value) => { containment = value; containmentFailed = false; draw(); }, () => { containmentFailed = true; draw(); }) : () => {};
  document.addEventListener('visibilitychange', queue);
  void read();
  return () => { controller.abort(); clearTimeout(timer); document.removeEventListener('visibilitychange', queue); stop(); stopContainment(); root.replaceChildren(); };
}
