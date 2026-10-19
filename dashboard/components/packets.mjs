// mount(root, services, options) returns dispose. Services provide transport and selection.
// The packet list for the selected host's links, or for every guest-facing
// link when no host is selected, merged as the CLI dashboard merges them.
import { scoped, listen } from '../dom.mjs';
import { createPackets } from '../packets.mjs';
import { fmtCount } from '../format.mjs';

// What the pair filter tells the viewer: an event names addresses and ports,
// and packets are matched by them, never by time.
export const APPROXIMATE = 'Approximate: matched by address and port, not by connection.';

export function mount(root, services, options = {}) {
  const { $, el } = scoped(root);
  if (!$('drawer')) structure(root, el);
  const view = createPackets({
    $, el, ...services.transport, fmtCount, fit() {}, ...options,
    placeholder: options.placeholder || (() => 'Select a packet to see its layers.'),
    ...(options.drawer ? {} : { pcapLabel: 'pcapng' }),
  });
  options.onReady?.(view);
  let animation;
  // A list with links open but nothing captured yet says so.
  const note = $('plist-empty');
  const frame = () => {
    view.flush();
    if (note) {
      const empty = !$('drawer').hidden && !$('prows').children.length;
      if (note.hidden === empty) note.hidden = !empty;
    }
    animation = requestAnimationFrame(frame);
  };
  animation = requestAnimationFrame(frame);
  const cleanup = [];
  let watch, request, generation = 0, current = '';
  let nodes = new Map(), edges = new Map();
  let selected = services.selection?.get() || { host: null, links: [] };

  function empty(text) {
    view.close();
    $('drawer').hidden = false;
    $('drawer-title').textContent = 'Packets';
    $('prows').replaceChildren();
    el('td', { colspan: 8, text }, el('tr', { class: 'gap' }, $('prows')));
  }
  function show(links, label) {
    const members = links.map((id) => edges.get(id) || { id, c: [0, 0, 0, 0] })
      .sort((a, b) => (b.c?.[0] || 0) + (b.c?.[2] || 0) - (a.c?.[0] || 0) - (a.c?.[2] || 0));
    const kept = members.slice(0, 32);
    const key = `${label}:${kept.map((edge) => edge.id).join(',')}`;
    if (current === key) return;
    current = key;
    if (!kept.length) {
      empty(label === 'All hosts' ? 'No packets yet. They appear here as the world sends them.' : `${label} has no links yet. Its packets appear here once its network is up.`);
      return;
    }
    view.openLinks(label, 'network', kept.map((e) => ({ e, flip: nodes.get(e.b)?.kind === 'sandbox' })), '', members.length);
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
      current = '';
      empty(`Packets are unavailable: ${error.message}`);
    }
  }

  if (!options.drawer) {
    $('close-drawer').hidden = true;
    $('grip').hidden = true;
    watch = services.watch();
    const on = (name, callback) => cleanup.push(listen(watch, name, (event) => callback(JSON.parse(event.data))));
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
    cleanup.push(services.selection.subscribe((selection) => {
      if (selected.host === selection.host && selected.links.join(',') === selection.links.join(',')) return;
      selected = selection;
      void scope();
    }));
    // An event's address pair, chosen in the events panel.
    if (services.packetPair) {
      const badge = $('pair'), text = $('pair-text');
      cleanup.push(listen($('pair-clear'), 'click', () => services.packetPair.set(null)));
      cleanup.push(services.packetPair.subscribe((pair) => {
        view.setPair(pair && [pair.local, pair.peer]);
        badge.hidden = !pair;
        text.textContent = pair ? `${pair.local} ↔ ${pair.peer}. ${APPROXIMATE}` : '';
      }));
    }
    void scope();
  }
  return () => {
    generation++;
    request?.abort();
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
  el('input', { id: 'pfilter', type: 'search', placeholder: 'Filter packets', 'aria-label': 'Filter packets', autocomplete: 'off' }, head);
  el('button', { id: 'pause', class: 'button', type: 'button', text: 'Pause' }, head);
  const pcap = el('button', { id: 'pcap', class: 'button', type: 'button', title: 'Download these packets as pcapng, for Wireshark' }, head);
  const svg = el('svg:svg', { viewBox: '0 0 16 16', 'aria-hidden': 'true' }, pcap);
  el('svg:path', { d: 'M8 2v8m0 0L5 7m3 3 3-3M3 13h10', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, svg);
  el('span', { id: 'pcap-label', text: 'pcapng' }, pcap);
  el('button', { id: 'close-drawer', class: 'button', type: 'button', text: 'Close' }, head);
  const dirs = el('div', { class: 'dirs', hidden: '' }, drawer);
  for (const id of ['dir-a', 'dir-b']) el('span', { id }, dirs);
  el('p', { id: 'sampled', class: 'sampled', hidden: '' }, drawer);
  const pair = el('p', { id: 'pair', class: 'pair-note', hidden: '' }, drawer);
  el('span', { id: 'pair-text' }, pair);
  el('button', { id: 'pair-clear', class: 'text-button', type: 'button', text: 'Show all packets' }, pair);
  const body = el('div', { class: 'drawer-body' }, drawer);
  const list = el('div', { class: 'plist-wrap' }, body);
  const scroller = el('div', { id: 'plist', class: 'plist' }, list);
  const table = el('table', {}, scroller);
  const cols = el('colgroup', {}, table);
  for (const name of ['c-no', 'c-time', 'c-dir', 'c-addr', 'c-addr', 'c-proto', 'c-len', 'c-info']) el('col', { class: name }, cols);
  const row = el('tr', {}, el('thead', {}, table));
  for (const text of ['No.', 'Time', '', 'Source', 'Destination', 'Protocol', 'Length', 'Info']) {
    const th = el('th', { text, scope: 'col' }, row);
    if (!text) th.setAttribute('aria-label', 'Direction');
  }
  el('tbody', { id: 'prows' }, table);
  el('button', { id: 'jump-packets', class: 'jump', type: 'button', hidden: '' }, list);
  el('p', { id: 'plist-empty', class: 'list-empty', role: 'status', hidden: '', text: 'No packets yet. They appear here as the world sends them.' }, list);
  const detail = el('div', { class: 'detail' }, body);
  el('div', { id: 'tree', class: 'tree' }, detail);
  const hex = el('div', { id: 'hex', class: 'hex', hidden: '' }, detail);
  el('div', { id: 'hex-tabs', class: 'hex-tabs' }, hex);
  el('pre', { id: 'hex-dump' }, hex);
}
