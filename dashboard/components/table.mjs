// mount(root, services, options) returns dispose. Services provide replacement state snapshots.
import { scoped, reconcile } from '../dom.mjs';
import { fmtBytes, fmtDuration } from '../format.mjs';

function pointer(value, path) {
  if (!path) return value;
  for (const part of path.slice(1).split('/')) {
    const key = part.replace(/~1/g, '/').replace(/~0/g, '~');
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)) return undefined;
    value = value[key];
  }
  return value;
}

function cell(value, format) {
  if (value === undefined || value === null) return '—';
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (format === 'bytes') return fmtBytes(value);
    if (format === 'time') return fmtDuration(value);
    if (format === 'number') return value.toLocaleString('en-US');
  }
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

// What each table root shows: its columns, and its rows by key.
const tables = new WeakMap();

// Renders rows under `root`, updating the table in place: rows keep their
// elements, and only rows whose text changed are built again and marked new.
// `options.key(row)` names a row; without it, a row is named by its text.
export function render(root, rows, columns, options = {}) {
  const { el } = scoped(root);
  // Every column but the last takes the width of its content; the last
  // takes the rest. Numbers align right, headers with them.
  const kind = (column, i) => [
    ['number', 'bytes', 'time'].includes(column.format) ? 'numeric' : '',
    i < columns.length - 1 ? 'fit' : '',
  ].filter(Boolean).join(' ');
  const signature = JSON.stringify(columns);
  let table = tables.get(root);
  if (!table || table.signature !== signature || !root.contains(table.node)) {
    const node = el('table', { class: 'data-table' });
    const head = el('tr', {}, el('thead', {}, node));
    columns.forEach((column, i) => el('th', { text: column.label, scope: 'col', class: kind(column, i) }, head));
    table = { node, body: el('tbody', {}, node), rows: new Map(), signature, empty: null };
    tables.set(root, table);
    root.replaceChildren(node);
  }
  const top = root.scrollTop;
  const seen = new Map();
  const items = rows.map((row) => {
    const texts = columns.map((column) => cell(pointer(row, column.pointer), column.format));
    const name = options.key?.(row) ?? texts.join('\u0000');
    const repeat = seen.get(name) || 0;
    seen.set(name, repeat + 1);
    return { row, texts, key: `${name}\u0000${repeat}` };
  });
  table.empty?.remove();
  table.empty = null;
  reconcile(table.body, items, (item) => item.key, () => {
    const node = el('tr');
    return { node, cells: columns.map((column, i) => el('td', { class: kind(column, i) }, node)), texts: [] };
  }, (entry, item, fresh) => {
    item.texts.forEach((text, i) => {
      if (entry.texts[i] === text) return;
      const td = entry.cells[i];
      td.replaceChildren();
      if (columns[i].format === 'status' && text !== '—') el('span', { class: 'pill', text }, td);
      else td.textContent = text;
    });
    entry.texts = item.texts;
    entry.node.classList.toggle('moment', Boolean(options.moment?.(item.row)));
    if (fresh) entry.node.classList.add('new-row');
  }, table.rows);
  if (!rows.length) {
    table.empty = el('tr', {}, table.body);
    el('td', { colspan: Math.max(1, columns.length), class: 'empty-cell', text: 'No rows yet. They appear here as the world runs.' }, table.empty);
  }
  root.scrollTop = top;
}

export function mount(root, services, options) {
  const { el } = scoped(root);
  const status = el('p', { class: 'loss-note', role: 'status', text: 'Loading…' }, root);
  const body = el('div', { class: 'table-scroll' }, root);
  const stop = services.state(options.state, (snapshot) => {
    const value = snapshot.value;
    render(body, Array.isArray(value) ? value : value === null ? [] : [value], options.columns);
    status.textContent = snapshot.status?.too_large ? 'This state exceeded its size limit. The last complete rows are shown.' : '';
  }, (error) => {
    status.textContent = services.stopped() ? 'The run has stopped, so these rows can no longer be loaded.' : `Could not load rows: ${error.message}`;
  });
  return () => { stop(); root.replaceChildren(); };
}
