// mount(root, services, options) returns dispose. Services provide replacement state snapshots.
import { scoped } from '../dom.mjs';
import { fmtBytes, fmtDuration } from '../format.mjs';

export function pointer(value, path) {
  if (!path) return value;
  for (const part of path.slice(1).split('/')) {
    const key = part.replace(/~1/g, '/').replace(/~0/g, '~');
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)) return undefined;
    value = value[key];
  }
  return value;
}

export function cell(value, format) {
  if (value === undefined || value === null) return '—';
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (format === 'bytes') return fmtBytes(value);
    if (format === 'time') return fmtDuration(value);
    if (format === 'number') return value.toLocaleString('en-US');
  }
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

export function render(root, rows, columns, options = {}) {
  const { el } = scoped(root);
  const top = root.scrollTop;
  const previous = new Set([...root.querySelectorAll('tbody tr')].map((row) => row.textContent));
  const table = el('table', { class: 'data-table' });
  const head = el('tr', {}, el('thead', {}, table));
  for (const column of columns) el('th', { text: column.label, scope: 'col' }, head);
  const body = el('tbody', {}, table);
  for (const row of rows) {
    const tr = el('tr', {}, body);
    if (options.moment?.(row)) tr.classList.add('moment');
    for (const column of columns) {
      el('td', { text: cell(pointer(row, column.pointer), column.format), class: ['number', 'bytes', 'time'].includes(column.format) ? 'numeric' : '' }, tr);
    }
    if (!previous.has(tr.textContent)) tr.classList.add('new-row');
  }
  if (!rows.length) el('td', { colspan: Math.max(1, columns.length), text: 'No rows yet. They appear here as the world runs.' }, el('tr', {}, body));
  root.replaceChildren(table);
  root.scrollTop = top;
}

export function mount(root, services, options) {
  const { el } = scoped(root);
  const status = el('p', { role: 'status', text: 'Loading…' }, root);
  const body = el('div', { class: 'table-scroll' }, root);
  const stop = services.state(options.state, (snapshot) => {
    const value = snapshot.value;
    render(body, Array.isArray(value) ? value : value === null ? [] : [value], options.columns);
    status.textContent = snapshot.status?.too_large ? 'This state exceeded its size limit. The last complete rows are shown.' : '';
  }, (error) => { status.textContent = `Could not load rows: ${error.message}`; });
  return () => { stop(); root.replaceChildren(); };
}
