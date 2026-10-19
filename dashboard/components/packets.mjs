// mount(root, services, options) returns dispose. Services provide transport and selection.
import { scoped } from '../dom.mjs';
import { createPackets } from '../packets.mjs';
import { fmtCount } from '../format.mjs';

export function mount(root, services, options = {}) {
  const { $, el } = scoped(root);
  if (!$('drawer')) structure(root, el);
  const view = createPackets({ $, el, ...services.transport, fmtCount, fit() {}, ...options });
  options.onReady?.(view);
  let animation;
  const frame = () => { view.flush(); animation = requestAnimationFrame(frame); };
  animation = requestAnimationFrame(frame);
  let stopSelection = () => {};
  let watch;
  const cleanup = [];
  let request;
  let generation = 0;
  let current = '';
  let nodes = new Map();
  let edges = new Map();
  let selected = services.selection?.get() || { host: null, links: [] };

  function show(links, label) {
    const members = links.map((id) => edges.get(id) || { id, c: [0, 0, 0, 0] })
      .sort((a, b) => (b.c?.[0] || 0) + (b.c?.[2] || 0) - (a.c?.[0] || 0) - (a.c?.[2] || 0));
    const kept = members.slice(0, 32);
    const key = `${label}:${kept.map((edge) => edge.id).join(',')}`;
    if (current === key) return;
    current = key;
    if (!kept.length) {
      view.close();
      $('drawer').hidden = false;
      $('prows').replaceChildren();
      $('drawer-title').textContent = 'Packets';
      $('tree').textContent = 'No packets yet. They appear here as the world sends them.';
      return;
    }
    view.openLinks(label, 'Network', kept.map((e) => ({ e, flip: nodes.get(e.b)?.kind === 'sandbox' })), '', members.length);
  }

  async function scope() {
    const attempt = ++generation;
    request?.abort();
    if (selected.links.length) return show(selected.links, selected.host || 'Selected links');
    if (!selected.host) {
      return show([...edges.values()].filter((e) => nodes.get(e.a)?.kind === 'sandbox' || nodes.get(e.b)?.kind === 'sandbox').map((e) => e.id), 'All hosts');
    }
    request = new AbortController();
    try {
      const value = await services.transport.get(`/api/host/${selected.host}/links`, {}, request.signal);
      if (attempt === generation) show(value.links, selected.host);
    } catch (error) {
      if (attempt !== generation || request.signal.aborted) return;
      view.close();
      $('drawer').hidden = false;
      $('tree').textContent = `Packets are unavailable: ${error.message}`;
    }
  }

  if (!options.drawer) {
    $('close-drawer').hidden = true;
    $('grip').hidden = true;
    watch = services.transport.watch();
    const on = (name, callback) => {
      const listener = (event) => callback(JSON.parse(event.data));
      watch.addEventListener(name, listener);
      cleanup.push(() => watch.removeEventListener(name, listener));
    };
    on('snapshot', (snapshot) => {
      nodes = new Map(snapshot.nodes.map((node) => [node.id, node]));
      edges = new Map(snapshot.edges.map((edge) => [edge.id, { ...edge, c: snapshot.counters[edge.id] }]));
      void scope();
    });
    on('node', (node) => { nodes.set(node.id, node); void scope(); });
    on('node_end', ({ id }) => { nodes.delete(id); void scope(); });
    on('edge', (edge) => { edges.set(edge.id, edge); void scope(); });
    on('edge_end', ({ id }) => { edges.delete(id); void scope(); });
    on('counters', ({ edges: counts }) => {
      for (const [id, c] of Object.entries(counts || {})) if (edges.has(id)) edges.get(id).c = c;
    });
    stopSelection = services.selection.subscribe((selection) => {
      if (selected.host === selection.host && selected.links.join(',') === selection.links.join(',')) return;
      selected = selection;
      void scope();
    });
    void scope();
  }
  return () => {
    generation++;
    request?.abort();
    stopSelection();
    cleanup.forEach((remove) => remove());
    watch?.close();
    cancelAnimationFrame(animation);
    view.dispose();
  };
}

function structure(root, el) {
  const drawer = el('section', { id: 'drawer', class: 'drawer packet-panel', 'aria-label': 'Packets' }, root);
  el('div', { id: 'grip', class: 'grip' }, drawer);
  const head = el('div', { class: 'drawer-head' }, drawer);
  el('h2', { id: 'drawer-title', text: 'Packets' }, head);
  const dirs = el('div', { class: 'dirs' }, head);
  for (const id of ['dir-a', 'dir-b', 'sampled']) el('span', { id }, dirs);
  el('input', { id: 'pfilter', type: 'search', placeholder: 'Filter packets', 'aria-label': 'Filter packets' }, head);
  el('button', { id: 'jump-packets', type: 'button', hidden: '' }, head);
  el('button', { id: 'pause', type: 'button', text: 'Pause' }, head);
  const pcap = el('button', { id: 'pcap', type: 'button' }, head);
  el('span', { id: 'pcap-label', text: 'Capture for Wireshark' }, pcap);
  el('button', { id: 'close-drawer', type: 'button', text: 'Close' }, head);
  const body = el('div', { class: 'drawer-body' }, drawer);
  const list = el('div', { id: 'plist', class: 'plist' }, body);
  const table = el('table', {}, list);
  const row = el('tr', {}, el('thead', {}, table));
  for (const text of ['No.', 'Time', 'Direction', 'Source', 'Destination', 'Protocol', 'Length', 'Info']) el('th', { text }, row);
  el('tbody', { id: 'prows' }, table);
  const detail = el('div', { class: 'detail' }, body);
  el('div', { id: 'tree', class: 'tree' }, detail);
  const hex = el('div', { id: 'hex', class: 'hex', hidden: '' }, detail);
  el('div', { id: 'hex-tabs', class: 'hex-tabs' }, hex);
  el('pre', { id: 'hex-dump' }, hex);
}
