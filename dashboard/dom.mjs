import { fmtCount } from './format.mjs';

// DOM helpers shared by the page and its packet list.
const SVGNS = 'http://www.w3.org/2000/svg';

const el = (tag, attrs = {}, parent, document = parent?.ownerDocument || globalThis.document) => {
  const e = tag.startsWith('svg:') ? document.createElementNS(SVGNS, tag.slice(4)) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'text') e.textContent = v;
    else if (k === 'class') e.setAttribute('class', v);
    else e.setAttribute(k, v);
  }
  if (parent) parent.appendChild(e);
  return e;
};

export { el };

export function scoped(root) {
  return {
    $: (id) => root.id === id ? root : root.querySelector(`#${id}`),
    el: (tag, attrs, parent) => el(tag, attrs, parent, root.ownerDocument),
  };
}

// Updates a list in place by key, so live rows neither jump nor lose focus.
// `retained` maps each key to an entry whose `node` is a child of `parent`,
// and `parent` holds only those nodes. New items get `create(item)`; every
// item then gets `update(entry, item, fresh)`. Entries for items no longer
// wanted are removed, and a node moves only when its place changes.
export function reconcile(parent, items, key, create, update, retained) {
  const wanted = new Set(items.map(key));
  for (const [id, entry] of retained) if (!wanted.has(id)) { entry.node.remove(); retained.delete(id); }
  items.forEach((item, index) => {
    const id = key(item);
    let entry = retained.get(id);
    const fresh = !entry;
    if (!entry) { entry = create(item); retained.set(id, entry); }
    update(entry, item, fresh);
    if (parent.children[index] !== entry.node) parent.insertBefore(entry.node, parent.children[index] || null);
  });
}

export function listen(target, name, callback, options) {
  target.addEventListener(name, callback, options);
  return () => target.removeEventListener(name, callback, options);
}

// Small icons keep their meaning in the adjacent text or accessible name.
export function icon(parent, kind) {
  const paths = {
    chevron: 'M6 3l5 5-5 5',
    check: 'M3 8l3 3 7-7',
    warning: 'M8 2L1 14h14L8 2zM8 6v4M8 12v.1',
    download: 'M8 2v8m0 0L5 7m3 3 3-3M3 13h10',
    close: 'M4 4l8 8M12 4l-8 8',
    neutral: 'M3 8h10',
  };
  const svg = el('svg:svg', { width: 16, height: 16, viewBox: '0 0 16 16', 'aria-hidden': 'true' }, parent);
  el('svg:path', { d: paths[kind], fill: 'none', stroke: 'currentColor', 'stroke-width': 1.5, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, svg);
  return svg;
}

// Both observation lists render their loss totals here.
export function lossLine(node, losses) {
  node.textContent = losses.filter((loss) => loss.count > 0).map((loss) => {
    const count = fmtCount(loss.count);
    if (loss.stream === 'packets') {
      if (loss.reason === 'policy') return `Policy: ${count} packets not kept`;
      if (loss.reason === 'sampling') return `Sampled: ${count} packets not copied`;
      if (loss.reason === 'overflow') return `Capture: ${count} copies refused`;
      if (loss.reason === 'eviction') return `Capture: ${count} copies evicted`;
    }
    if (loss.reason === 'subscriber') return `Subscriber: ${count} rows missed`;
    const stream = loss.stream[0].toUpperCase() + loss.stream.slice(1);
    if (loss.reason === 'truncation') return `${stream}: ${count} cut`;
    return `${stream}: ${count} lost (${loss.reason}).`;
  }).join(' · ');
  node.hidden = !node.textContent;
}

// A bounded tail with stable rows, shared by events and packets.
export function observationList(parent, { limit, key, create, update = () => {} }) {
  const rows = new Map();
  let items = [];
  function show(next) {
    items = next.slice(-limit);
    reconcile(parent, items, key, create, update, rows);
  }
  return {
    show,
    append(next) { show([...items, ...next]); },
    clear() { items = []; rows.clear(); parent.replaceChildren(); },
  };
}
