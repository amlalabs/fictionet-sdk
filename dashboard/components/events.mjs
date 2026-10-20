// mount(root, services, options) returns dispose. Services provide the graph
// model, selection and host names.
import { labelAction } from './labels.mjs';
import { labelChips } from '../packets.mjs';
import { eventText } from '../tables.mjs';
import { scoped, listen, reconcile, lossLine } from '../dom.mjs';
import { fmtRunTime } from '../format.mjs';
import { APPROXIMATE } from './packets.mjs';

const LIMIT = 500;

// The page's timeline: one line per event, newest first. A selected event
// opens its fields below its line. Arriving events render once per frame and
// update rows by key, so a flood of events never blocks the page.
export function mount(root, services, options = {}) {
  const { el } = scoped(root);
  const tools = el('div', { class: 'panel-tools' }, root);
  const filter = el('input', { type: 'search', class: 'text-field', 'aria-label': 'Filter events', placeholder: 'Filter events', autocomplete: 'off' }, tools);
  const jump = el('button', { class: 'jump', type: 'button', hidden: '' }, tools);
  const loss = el('p', { class: 'loss-note', role: 'status', hidden: '' }, root);
  const wrap = el('div', { class: 'list-wrap' }, root);
  const list = el('div', { class: 'event-list', role: 'list' }, wrap);
  const empty = el('p', { class: 'list-empty', role: 'status', hidden: '' }, wrap);
  const rows = new Map();
  const { state } = services.graph;
  let host = services.selection.get().host, chosen = services.selection.get().event?.seq ?? null;
  let pending = 0, paused = false, labels = [], connection = services.selection.get().event ? null : services.selection.get().connection;
  let frame = null, reported, missed = 0;
  const editing = () => [...list.querySelectorAll('form')].some((form) => !form.hidden);
  const newRows = new Set();
  const cleanup = [];
  const hostOf = (event) => services.hostOf(event.sandbox?.name);

  function select(event) {
    if (chosen === event.seq) {
      chosen = null;
      services.selection.set({ event: null, connection: null, request: null });
      return;
    }
    chosen = event.seq;
    services.selection.set({ host: hostOf(event), node: event.node || null, event, connection: event.conn ?? null, request: event.fields?.request_id ?? null, links: [] });
  }
  function details(event, parent) {
    const box = el('div', { class: 'event-detail' }, parent);
    const header = el('div', { class: 'event-detail-head' }, box);
    el('strong', { text: `Event ${event.seq} · ${event.source}.${event.kind}` }, header);
    labelAction(header, services, { kind: 'event', seq: event.seq }, 'Label', render);
    const dl = el('dl', { class: 'kv' }, box);
    const add = (key, value) => {
      if (value === null || value === undefined || value === '') return;
      el('dt', { text: key }, dl);
      el('dd', { class: 'mono', text: typeof value === 'object' ? JSON.stringify(value) : String(value) }, dl);
    };
    add('Time', `${event.at.toFixed(3)} s`);
    add('Task', event.task);
    add('Local', event.local);
    add('Peer', event.peer);
    if (event.local || event.peer) add('Transport', `${event.transport}${event.tls ? ', TLS' : ''}`);
    add('Server name', event.sni);
    add('Connection', event.conn);
    for (const [key, value] of Object.entries(event.fields || {})) add(key, value);
    if (event.local && event.peer) {
      const row = el('p', { class: 'event-actions' }, box);
      if (event.conn) labelAction(row, services, { kind: 'connection', id: event.conn, local: event.local, peer: event.peer }, 'Label connection', render);
      const show = el('button', { class: 'button', type: 'button', text: 'Show matching packets' }, row);
      el('span', { class: 'hint', text: APPROXIMATE }, row);
      show.addEventListener('click', () => services.showPackets({ local: event.local, peer: event.peer }));
    }
    return box;
  }
  function create(event) {
    const node = el('div', { class: 'event-item', role: 'listitem' });
    const line = el('button', { class: 'event-line', type: 'button' }, node);
    el('time', { text: fmtRunTime(event.at) }, line);
    el('span', { class: 'kind', text: `${event.source}.${event.kind}` }, line);
    const summary = el('span', { class: 'text' }, line);
    el('span', { class: 'event-summary', text: event.summary || eventText(event.fields) }, summary);
    const origin = hostOf(event) || event.task;
    if (origin) el('span', { class: 'pill', text: origin }, line);
    line.addEventListener('click', () => { select(event); render(); });
    return { node, line, summary, chips: '', detail: null };
  }
  function update(entry, event, fresh) {
    if (fresh && newRows.has(event.seq)) entry.node.classList.add('new-row');
    if (!entry.line) return;
    const open = chosen === event.seq;
    entry.line.setAttribute('aria-expanded', String(open));
    entry.node.classList.toggle('on', open);
    if (services.isMoment(event)) services.moment(entry.node);
    const chips = labels.filter((label) => label.target.kind === 'event' ? label.target.seq === event.seq : label.target.kind === 'connection' && label.target.id === event.conn);
    const signature = JSON.stringify(chips);
    if (signature !== entry.chips) {
      entry.chips = signature;
      for (const chip of entry.summary.querySelectorAll('.label-chip')) chip.remove();
      labelChips(entry.summary, chips);
    }
    if (open && !entry.detail) entry.detail = details(event, entry.node);
    else if (!open && entry.detail) { entry.detail.remove(); entry.detail = null; }
  }
  function render() {
    if (frame !== null) { cancelAnimationFrame(frame); frame = null; }
    const query = filter.value.trim().toLowerCase();
    const sandbox = services.sandboxOf(host);
    const events = state.events;
    const visible = events.filter((event) => (!sandbox || event.sandbox?.name === sandbox) && (!connection || event.conn === connection) && (!query || `${event.source}.${event.kind} ${JSON.stringify(event)}`.toLowerCase().includes(query)));
    const top = list.scrollTop;
    reconcile(list, visible.slice(-LIMIT).reverse(), (event) => event.seq, create, update, rows);
    empty.hidden = visible.length > 0;
    empty.textContent = events.length ? 'No events match.' : 'No events yet. They appear here as the world runs.';
    list.scrollTop = paused ? top : 0;
    newRows.clear();
    pending = 0;
    jump.hidden = true;
  }
  // However many events arrive, the list renders at most once per frame.
  function schedule() {
    if (frame === null) frame = requestAnimationFrame(() => { frame = null; render(); });
  }
  function status(value) {
    reported = value;
    const losses = (value?.losses || []).filter((item) => item.stream === 'events' || item.stream === 'topology');
    lossLine(loss, [...losses, { stream: 'events', reason: 'subscriber', count: missed }]);
    if (!loss.textContent && value?.incomplete) loss.textContent = 'The observation is incomplete.';
    loss.hidden = !loss.textContent;
  }
  cleanup.push(services.graph.subscribe((name, data) => {
    if (name === 'snapshot') { missed = (data.gaps || []).reduce((n, gap) => n + gap.missed, 0); status(state.status); schedule(); }
    if (name === 'gap') { missed += data.missed; status(reported); }
    if (name === 'status') status(state.status);
    if (name === 'event') {
      newRows.add(data.seq);
      if (!paused && !editing()) schedule();
      else { pending++; jump.textContent = `↑ ${pending} new`; jump.hidden = false; }
    }
    if (name === 'world_error') { loss.textContent = `Events are unavailable: ${data.error}`; loss.hidden = false; }
    // A reconnecting stream says so until it opens again.
    if (name === 'error') { loss.textContent = data.error; loss.hidden = false; }
    if (name === 'open') status(reported);
  }));
  status(state.status);
  cleanup.push(listen(filter, 'input', render));
  cleanup.push(listen(list, 'scroll', () => { paused = list.scrollTop > 24; }));
  cleanup.push(listen(jump, 'click', () => { paused = false; render(); }));
  cleanup.push(services.selection.subscribe((selection) => {
    const seq = selection.event?.seq ?? null;
    if (host !== selection.host || seq !== chosen || connection !== (selection.event ? null : selection.connection)) {
      connection = selection.event ? null : selection.connection;
      host = selection.host;
      chosen = seq;
      render();
      if (seq !== null) list.querySelector?.('.event-item.on')?.scrollIntoView?.({ block: 'nearest' });
    }
  }));
  if (services.labelState) cleanup.push(services.state(services.labelState, (value) => { labels = value.value || []; if (!editing()) schedule(); }));
  cleanup.push(services.onMoment(() => { if (!paused && !editing()) schedule(); }));
  render();
  return () => {
    if (frame !== null) cancelAnimationFrame(frame);
    cleanup.forEach((remove) => remove());
    root.replaceChildren();
  };
}
