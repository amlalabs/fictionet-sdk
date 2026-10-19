// Guest destinations projected by the observer, including startup traffic.
import { scoped } from '../dom.mjs';
import { cell, render } from './table.mjs';

const groups = [
  ['forwarded', 'Forwarded to the real internet'], ['served', 'Served by the world'],
  ['refused', 'Refused'], ['no_route', 'No route'],
];
const attempts = (row) => (row.requests || 0) + (row.packets || 0) || row.connections || 0;

export function mount(root, services) {
  const { el } = scoped(root), document = root.ownerDocument;
  const summary = el('div', { class: 'egress-summary', role: 'status' }, root);
  const status = el('p', { text: 'Loading destinations…' }, summary);
  const stayed = el('p', {}, summary);
  const pending = el('p', { class: 'egress-muted' }, summary);
  const body = el('div', { class: 'egress-groups' }, root);
  const details = el('details', { class: 'egress-lookups' }, root);
  const lookupSummary = el('summary', { text: 'DNS lookups (0)' }, details);
  const lookups = el('div', { class: 'table-scroll' }, details);
  const controller = new AbortController();
  const schedule = services.setTimeout || setTimeout, cancel = services.clearTimeout || clearTimeout;
  let timer, snapshot, selected, failed = false;
  function draw() {
    if (!snapshot) return;
    const sandbox = services.hosts?.find((host) => host.name === selected)?.sandbox || selected;
    const visible = (row) => !sandbox || row.sandbox === sandbox;
    const rows = snapshot.destinations.filter(visible);
    const origins = new Map();
    for (const row of rows.filter((row) => row.outcome === 'forwarded')) origins.set(row.by, (origins.get(row.by) || 0) + row.requests);
    status.replaceChildren();
    const incomplete = snapshot.dropped || snapshot.lost;
    el('span', { class: incomplete ? 'egress-warning' : 'egress-complete', text: incomplete ? '△ ' : '✓ ' }, status);
    if (incomplete) status.append(`This list may be incomplete: ${snapshot.dropped} attempts not kept, ${snapshot.lost} observations lost.`);
    else if (!origins.size) status.append('Nothing left the box.');
    else {
      status.append('Left the box: ');
      [...origins].forEach(([origin, count], i) => {
        if (i) status.append(', ');
        el('span', { class: 'mono', text: origin }, status);
        status.append(` (${count} requests)`);
      });
    }
    const count = (outcome) => rows.filter((row) => row.outcome === outcome).reduce((n, row) => n + attempts(row), 0);
    stayed.textContent = `${incomplete ? 'Observed in the world' : 'Everything else stayed in the world'}: ${count('served')} served, ${count('refused')} refused, ${count('no_route')} with no route.`;
    const open = (snapshot.pending || []).filter(visible).length;
    pending.textContent = open ? `${open} connections open, outcome not known yet` : '';
    const scroll = root.scrollTop;
    body.replaceChildren();
    for (const [outcome, title] of groups) {
      const group = rows.filter((row) => row.outcome === outcome);
      if (!group.length) continue;
      el('h3', { text: `${title} (${count(outcome)})` }, body);
      const table = el('table', { class: 'data-table' }, el('div', { class: 'table-scroll' }, body));
      const head = el('tr', {}, el('thead', {}, table));
      const columns = [...(!sandbox ? ['Guest'] : []), 'Destination', 'Transport', 'Answered by', 'Connections', 'Requests', 'Packets', 'First', 'Last'];
      columns.forEach((label) => el('th', { scope: 'col', text: label, class: ['Connections', 'Requests', 'Packets', 'First', 'Last'].includes(label) ? 'numeric' : '' }, head));
      const tbody = el('tbody', {}, table);
      for (const row of group) {
        const tr = el('tr', {}, tbody);
        if (!sandbox) el('td', { text: row.sandbox }, tr);
        const destination = el('td', { class: 'egress-destination' }, tr);
        if (row.name) el('div', { class: 'egress-name', text: row.name }, destination);
        el('div', { class: 'mono egress-muted', text: row.address }, destination);
        el('td', { text: row.transport }, tr);
        const by = el('td', { class: 'egress-answer', text: row.by === 'host package cache' ? 'the host package cache' : row.by }, tr);
        if (row.unanswered) el('div', { class: 'egress-muted', text: `${row.unanswered} ended without an answer` }, by);
        for (const key of ['connections', 'requests', 'packets']) el('td', { class: 'numeric', text: row[key] ? cell(row[key], 'number') : '—' }, tr);
        for (const key of ['first', 'last']) el('td', { class: 'numeric', text: `${Number(row[key].toFixed(3))} s` }, tr);
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
    cancel(timer);
    timer = schedule(read, document.hidden ? 10000 : 2000);
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
        status.textContent = `Could not load destinations: ${error.message}. The table may be incomplete.`;
      }
    } finally {
      if (!controller.signal.aborted) queue();
    }
  }
  document.addEventListener('visibilitychange', queue);
  void read();
  return () => { controller.abort(); cancel(timer); document.removeEventListener('visibilitychange', queue); stop(); root.replaceChildren(); };
}
