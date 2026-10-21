// mount(root, services, options) returns dispose. Services provide the
// transport, selection and graph model.
// The packet list for the selected host's links, or for every declared
// host's links when no host is selected, merged by the page server. A page
// with no declared hosts lists every sandbox's links.
import { labelAction } from './labels.mjs';
import { scoped, listen } from '../dom.mjs';
import { createPackets } from '../packets.mjs';
import { fmtCount } from '../format.mjs';
import { addressOf, conversationRows, createLanes, dnsRow } from './lanes.mjs';

// The page server merges at most this many links: the busiest are shown.
const MAX_MERGED = 32;

// What the pair filter tells the viewer: an event names addresses and ports,
// and packets are matched by them, never by time.
export const APPROXIMATE = 'Address and port match';
const STOPPED = 'Run stopped';

export function mount(root, services, options = {}) {
  const { $: lookup, el } = scoped(root);
  const support = structure(root, el, options.compact);
  const $ = (id) => support?.get(id) || lookup(id);
  const addresses = new Map(), dnsNames = new Map(), resolvers = new Set();
  const media = root.ownerDocument?.defaultView?.matchMedia('(prefers-reduced-motion: reduce)');
  const animations = new Map();
  function animate(node, transform, duration) {
    if (media?.matches || !node.animate) return;
    animations.get(node)?.cancel();
    const animation = node.animate([{ opacity: 0, transform }, { opacity: 1, transform: 'none' }], { duration, easing: 'cubic-bezier(.2,.7,.3,1)' });
    animations.set(node, animation);
    const finished = () => { if (animations.get(node) === animation) animations.delete(node); };
    animation.finished.then(finished, finished);
  }
  function name(value) {
    const address = addressOf(value);
    for (const host of services.hosts) if ((addresses.get(host.name) || []).includes(address)) return host.name;
    return services.endpointNames?.get().get(address) || dnsNames.get(address) || (resolvers.has(address) ? 'resolver' : value);
  }
  const lanes = options.compact ? createLanes($('packet-lanes'), { name, animate, local: (value) => [...addresses.values()].some((list) => list.includes(addressOf(value))), addressFor: (host) => [...(services.endpointNames?.get() || []), ...dnsNames].find(([, value]) => value === host)?.[0] }) : null;
  let animation, timer, disposed = false;
  function schedule() {
    if (disposed || animation !== undefined) return;
    clearTimeout(timer);
    animation = requestAnimationFrame(frame);
  }
  const view = createPackets({
    onDetail(packet, header) {
      labelAction(header, services, { kind: 'flow', link: packet.link, a: packet.src, b: packet.dst }, 'Label flow');
    },
    endpointLabel: (value) => name(value).replace(/^www\./, ''),
    onRow: (p) => lanes?.add(p),
    onClear: () => { lanes?.clear(); dnsNames.clear(); resolvers.clear(); },
    onReplay: (rows) => lanes?.replace(rows),
    onPending: schedule,
    animate,
    filterRows(rows) {
      for (const p of rows) {
        const dns = dnsRow(p);
        if (!dns) continue;
        resolvers.add(addressOf(dns.back ? p.src : p.dst));
        for (const answer of dns.answers) dnsNames.set(answer.address, dns.name);
      }
      const conversations = new Set(conversationRows(rows));
      for (const row of rows) row.quiet = !conversations.has(row);
      return services.packetFilter?.get() === 'every' ? rows : rows.filter((row) => !row.quiet);
    },
    $, el, ...services.transport, fmtCount, stopped: () => (services.stopped() ? STOPPED : null), hostColumn: true,
    ...options,
  });
  // An empty list says whether its links are still opening or have nothing
  // captured yet. Packets already received are about to be shown.
  const note = $('plist-empty');
  const frame = () => {
    animation = undefined;
    view.flush();
    if (options.compact) {
      if (view.queued() > 0) timer = setTimeout(schedule, 400);
      return;
    }
    const queued = view.queued();
    const empty = !$('drawer').hidden && !$('prows').children.length && queued <= 0;
    if (note.hidden === empty) note.hidden = !empty;
    const text = queued < 0 ? 'Loading packets…' : 'No packets';
    if (empty && note.textContent !== text) note.textContent = text;
    animation = requestAnimationFrame(frame);
  };
  schedule();
  const cleanup = [];
  if (options.compact) {
    if (services.packetFilter) cleanup.push(services.packetFilter.subscribe(() => view.refresh()));
    if (services.endpointNames) cleanup.push(services.endpointNames.subscribe(() => view.refresh()));
    if (media) cleanup.push(listen(media, 'change', () => {
      if (media.matches) { animations.forEach((animation) => animation.cancel()); animations.clear(); }
    }));
  }
  if (options.compact) for (const host of services.hosts) {
    if (host.status) cleanup.push(services.state(host.status, ({ value }) => { addresses.set(host.name, value?.addresses || []); view.refresh(); }));
  }
  const { state } = services.graph;
  const owners = new Map();
  let request, generation = 0, current = '';
  let selected = services.selection.get();

  function empty(text) {
    view.close();
    $('drawer').hidden = false;
    $('drawer-title').textContent = 'Packets';
    $('drawer-title').title = 'Packets';
    $('drawer-title').setAttribute('aria-label', 'Packets');
    $('prows').replaceChildren();
    lanes?.clear();
    if (!options.compact) el('td', { colspan: 9, text }, el('tr', { class: 'gap' }, $('prows')));
  }
  function show(links, label) {
    const members = links.map((id) => state.edges.get(id) || { id, c: [0, 0, 0, 0] })
      .sort((a, b) => (b.c?.[0] || 0) + (b.c?.[2] || 0) - (a.c?.[0] || 0) - (a.c?.[2] || 0));
    const kept = members.slice(0, MAX_MERGED);
    const membersWithHosts = kept.map((e) => {
      const node = [state.nodes.get(e.a), state.nodes.get(e.b)].find((node) => node?.kind === 'sandbox');
      return { e, flip: state.nodes.get(e.b)?.kind === 'sandbox', host: services.hostLabel(node?.name) || owners.get(e.id) };
    });
    const key = `${label}:${membersWithHosts.map(({ e, host, flip }) => `${e.id}:${host}:${flip}`).join(',')}`;
    if (current === key) return;
    current = key;
    if (!kept.length) {
      empty(label === 'All hosts' ? 'No packets' : `${label} · No links`);
      return;
    }
    view.openLinks(label, 'network', membersWithHosts, '', members.length);
  }
  async function scope() {
    // Opening before the graph is known would open the stream again once it
    // is, since each link's host and direction come from the graph.
    if (!state.known) return;
    // A stopped run's links can no longer be read, so the list keeps what it
    // shows.
    if (current && services.stopped()) return;
    const attempt = ++generation;
    request?.abort();
    if (selected.links.length) show(selected.links, selected.host || 'Selected links');
    // A sandbox the page does not declare, such as the kit's admin host, is
    // not one of its hosts.
    const declared = new Set(services.hosts.map((host) => host.sandbox));
    const guest = (node) => node?.kind === 'sandbox' && (!declared.size || declared.has(node.name));
    const live = [...state.edges.values()].filter((e) => guest(state.nodes.get(e.a)) || guest(state.nodes.get(e.b))).map((e) => e.id);
    if (!selected.host && !selected.links.length) {
      show(live, 'All hosts');
    }
    const hosts = selected.host ? [selected.host] : services.hosts.map((host) => host.name);
    if (!hosts.length) return;
    request = new AbortController();
    try {
      const values = await Promise.all(hosts.map((host) => services.transport.get(`/api/host/${host}/links`, {}, request.signal)));
      if (attempt !== generation) return;
      values.forEach((value, index) => value.links.forEach((link) => owners.set(link, hosts[index])));
      if (selected.links.length) show(selected.links, selected.host || 'Selected links');
      else show([...new Set([...(selected.host ? [] : live), ...values.flatMap((value) => value.links)])], selected.host || 'All hosts');
    } catch (error) {
      if (attempt !== generation || request.signal.aborted) return;
      current = '';
      empty(services.stopped() ? STOPPED : `Packets are unavailable: ${error.message}`);
    }
  }

  if (services.labelState) cleanup.push(services.state(services.labelState, (value) => view.setLabels(value.value || [])));
  // A new graph, node or link may change which links are listed. A link that
  // ends keeps its rows: its stream says when it closed.
  cleanup.push(services.graph.subscribe((name) => {
    if (['snapshot', 'node', 'edge'].includes(name)) void scope();
  }));
  cleanup.push(services.selection.subscribe((selection) => {
    if (selected.host === selection.host && selected.links.join(',') === selection.links.join(',')) return;
    selected = selection;
    void scope();
  }));
  // An event's address pair, chosen in the events panel.
  const badge = $('pair'), text = $('pair-text');
  cleanup.push(listen($('pair-clear'), 'click', () => services.packetPair.set(null)));
  cleanup.push(services.packetPair.subscribe((pair) => {
    view.setPair(pair && [pair.local, pair.peer]);
    badge.hidden = !pair;
    text.textContent = pair ? `${pair.local} ↔ ${pair.peer}. ${APPROXIMATE}` : '';
  }));
  void scope();
  return () => {
    disposed = true;
    lanes?.dispose();
    generation++;
    request?.abort();
    cleanup.forEach((remove) => remove());
    cancelAnimationFrame(animation);
    clearTimeout(timer);
    animations.forEach((animation) => animation.cancel());
    animations.clear();
    view.dispose();
  };
}

function structure(root, el, compact = false) {
  const drawer = el('section', { id: 'drawer', class: `drawer packet-panel${compact ? ' app-packets' : ''}`, 'aria-label': 'Packets' }, root);
  const head = el('div', { class: 'drawer-head' }, drawer);
  el('h2', { id: 'drawer-title', text: 'Packets' }, head);
  el('input', { id: 'pfilter', type: 'search', placeholder: 'Filter packets', 'aria-label': 'Filter packets', autocomplete: 'off' }, head);
  el('button', { id: 'jump-packets', class: 'jump', type: 'button', hidden: '' }, head);
  el('button', { id: 'pause', class: 'button', type: 'button', text: 'Pause' }, head);
  const pcap = el('button', { id: 'pcap', class: 'button', type: 'button', title: 'Download these packets as pcapng, for Wireshark' }, head);
  const svg = el('svg:svg', { viewBox: '0 0 16 16', 'aria-hidden': 'true' }, pcap);
  el('svg:path', { d: 'M8 2v8m0 0L5 7m3 3 3-3M3 13h10', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, svg);
  el('span', { id: 'pcap-label', text: 'pcapng' }, pcap);
  const dirs = el('div', { class: 'dirs', hidden: '' }, drawer);
  for (const id of ['dir-a', 'dir-b']) el('span', { id }, dirs);
  el('p', { id: 'sampled', class: 'sampled', hidden: '' }, drawer);
  const pair = el('p', { id: 'pair', class: 'pair-note', hidden: '' }, drawer);
  el('span', { id: 'pair-text' }, pair);
  el('button', { id: 'pair-clear', class: 'text-button', type: 'button', text: 'Show all packets' }, pair);
  if (compact) el('div', { id: 'packet-lanes', class: 'packet-lanes', 'aria-label': 'Site conversations' }, drawer);
  const body = el('div', { class: 'drawer-body' }, drawer);
  const list = el('div', { class: 'plist-wrap' }, body);
  const scroller = el('div', { id: 'plist', class: 'plist', ...(compact ? { tabindex: '0', role: 'region', 'aria-label': 'Decoded packets' } : {}) }, list);
  const table = el('table', {}, scroller);
  const cols = el('colgroup', {}, table);
  for (const name of ['c-no', 'c-time', 'c-dir', 'c-host', 'c-src', 'c-dst', 'c-proto', 'c-len', 'c-info']) el('col', { class: name }, cols);
  const row = el('tr', {}, el('thead', {}, table));
  for (const [index, text] of ['No.', 'Time', '', 'Host', 'Source', 'Destination', 'Protocol', 'Length', 'Info'].entries()) {
    const th = el('th', { text, scope: 'col', class: ['c-no', 'c-time', 'c-dir', 'c-host', 'c-src', 'c-dst', 'c-proto', 'c-len', 'c-info'][index] }, row);
    if (!text) th.setAttribute('aria-label', 'Direction');
  }
  el('tbody', { id: 'prows' }, table);
  el('p', { id: 'plist-empty', class: 'list-empty', role: 'status', hidden: '', text: 'No packets' }, list);
  const detail = el('div', { class: 'detail' }, body);
  el('div', { id: 'tree', class: 'tree' }, detail);
  const hex = el('div', { id: 'hex', class: 'hex', hidden: '' }, detail);
  el('div', { id: 'hex-tabs', class: 'hex-tabs' }, hex);
  el('pre', { id: 'hex-dump' }, hex);
  if (compact) {
    const support = new Map(['drawer-title', 'pfilter', 'jump-packets', 'pause', 'pcap', 'pcap-label', 'dir-a', 'dir-b', 'sampled', 'pair', 'pair-text', 'pair-clear', 'tree', 'hex', 'hex-tabs', 'hex-dump', 'plist-empty'].map((id) => [id, root.querySelector(`#${id}`)]));
    for (const node of [head, dirs, support.get('sampled'), pair, detail, table.querySelector('thead'), cols, support.get('plist-empty')]) node.remove();
    return support;
  }
}
