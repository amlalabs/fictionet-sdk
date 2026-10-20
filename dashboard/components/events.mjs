import { labelAction, labelChips } from './labels.mjs';
// mount(root, services, options) returns dispose. Services provide the shared
// watch, selection and host names.
import { scoped, listen } from '../dom.mjs';
import { fmtRunTime } from '../format.mjs';
import { APPROXIMATE } from './packets.mjs';

// The CLI dashboard's side panel list of recent events.
export function renderEvents(parent, events, { el, state, drawnSource, tone, focusNode, select, onEvent, isMoment = () => false, newRows = new Set(), limit = 60 }) {
    if (!events.length) {
      el('p', { class: 'quiet', text: 'No events yet. They appear here as the world runs.' }, parent);
      return;
    }
    const ul = el('ul', { class: 'rows' }, parent);
    for (const n of events.slice(-limit).reverse()) {
      const li = el('li', { class: 'event-row' }, ul);
      if (isMoment(n)) li.classList.add('moment');
      if (newRows.has(n.seq)) li.classList.add('new-row');
      el('time', { text: fmtRunTime(n.at) }, li);
      const node = state.nodes.get(n.node) || drawnSource(n);
      const head = el('span', {}, li);
      el('span', { class: `kind ${tone(n)}`, text: `${n.source}.${n.kind}` }, head);
      if (n.task || node) {
        head.append(' from ');
        const b = el('button', { class: 'link', type: 'button', text: n.task || node.name }, head);
        b.title = n.file ? `${n.file}:${n.line}` : '';
        b.addEventListener('click', () => {
          if (state.nodes.get(n.node)) focusNode(n.node);
          else select({ kind: 'ended', id: n.node, event: n });
        });
      }
      const summary = el(onEvent ? 'button' : 'span', { class: 'text', text: n.summary || eventText(n.fields) }, li);
      if (onEvent) {
        summary.type = 'button';
        summary.addEventListener('click', () => onEvent(n));
      }
    }
  }

  /// An event's fields as `key value` pairs, or as JSON when they are not
  /// an object.
export function eventText(data) {
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      return Object.entries(data)
        .map(([k, v]) => `${k} ${typeof v === 'object' ? JSON.stringify(v) : v}`)
        .join(', ');
    }
    return JSON.stringify(data);
  }

const LIMIT = 500;

// The page's timeline: one line per event, newest first. A selected event
// opens its fields below its line.
export function mount(root, services, options = {}) {
  const { el } = scoped(root);
  const tools = el('div', { class: 'panel-tools' }, root);
  const filter = el('input', { type: 'search', class: 'text-field', 'aria-label': 'Filter events', placeholder: 'Filter events', autocomplete: 'off' }, tools);
  const jump = el('button', { class: 'jump', type: 'button', hidden: '' }, tools);
  const loss = el('p', { class: 'loss-note', role: 'status', hidden: '' }, root);
  const wrap = el('div', { class: 'list-wrap' }, root);
  const list = el('div', { class: 'event-list', role: 'list' }, wrap);
  let events = [], host = services.selection.get().host, chosen = services.selection.get().event?.seq ?? null;
  let pending = 0, paused = false, labels = [], connection = services.selection.get().event ? null : services.selection.get().connection;
  const editing = () => [...list.querySelectorAll('form')].some((form) => !form.hidden);
  const newRows = new Set();
  const source = services.watch();
  const cleanup = [];
  const on = (name, callback) => cleanup.push(listen(source, name, (event) => callback(event.data ? JSON.parse(event.data) : null)));
  const hostOf = (event) => services.hosts?.find((item) => item.sandbox === event.sandbox?.name || item.name === event.sandbox?.name)?.name || null;

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
    if (event.local && event.peer && (event.conn || services.packetPair)) {
      const row = el('p', { class: 'event-actions' }, box);
      if (event.conn) labelAction(row, services, { kind: 'connection', id: event.conn, local: event.local, peer: event.peer }, 'Label connection', render);
      if (!services.packetPair) return;
      const show = el('button', { class: 'button', type: 'button', text: 'Show matching packets' }, row);
      el('span', { class: 'hint', text: APPROXIMATE }, row);
      show.addEventListener('click', () => services.showPackets?.({ local: event.local, peer: event.peer }));
    }
  }
  function render() {
    const query = filter.value.trim().toLowerCase();
    const sandbox = services.hosts?.find((item) => item.name === host)?.sandbox || host;
    const visible = events.filter((event) => (!sandbox || event.sandbox?.name === sandbox) && (!connection || event.conn === connection) && (!query || `${event.source}.${event.kind} ${JSON.stringify(event)}`.toLowerCase().includes(query)));
    const top = list.scrollTop;
    list.replaceChildren();
    if (!visible.length) {
      el('p', { class: 'empty-note', text: events.length ? 'No events match.' : 'No events yet. They appear here as the world runs.' }, list);
    }
    for (const event of visible.slice(-LIMIT).reverse()) {
      const item = el('div', { class: 'event-item', role: 'listitem' }, list);
      if (event.source === 'events' && event.kind === 'dropped') {
        item.classList.add('loss-row');
        el('p', { text: `${event.fields?.count ?? 'Some'} events were lost here (${event.fields?.reason || 'dropped'}).` }, item);
        continue;
      }
      const line = el('button', { class: 'event-line', type: 'button', 'aria-expanded': String(chosen === event.seq) }, item);
      if (services.isMoment?.(event)) services.moment?.(item);
      if (newRows.has(event.seq)) item.classList.add('new-row');
      if (chosen === event.seq) item.classList.add('on');
      el('time', { text: fmtRunTime(event.at) }, line);
      el('span', { class: 'kind', text: `${event.source}.${event.kind}` }, line);
      const summary = el('span', { class: 'text' }, line);
      el('span', { class: 'event-summary', text: event.summary || eventText(event.fields) }, summary);
      labelChips(summary, labels.filter((label) => label.target.kind === 'event' ? label.target.seq === event.seq : label.target.kind === 'connection' && label.target.id === event.conn));
      const origin = hostOf(event) || event.task;
      if (origin) el('span', { class: 'pill', text: origin }, line);
      line.addEventListener('click', () => { select(event); render(); });
      if (chosen === event.seq) details(event, item);
    }
    list.scrollTop = paused ? top : 0;
    newRows.clear();
    pending = 0;
    jump.hidden = true;
  }
  function status(value) {
    const losses = (value?.losses || []).filter((item) => item.stream === 'events' || item.stream === 'topology');
    loss.textContent = losses.map((item) => `${item.stream === 'events' ? 'Events' : 'Topology'}: ${item.count} lost (${item.reason}).`).join(' ');
    if (!loss.textContent && value?.incomplete) loss.textContent = 'The observation is incomplete.';
    loss.hidden = !loss.textContent;
  }
  on('snapshot', (snapshot) => {
    events = snapshot.events.slice(-LIMIT);
    status(snapshot.status);
    render();
  });
  on('status', ({ status: value }) => status(value));
  on('event', (event) => {
    events.push(event);
    if (events.length > LIMIT) events = events.slice(-LIMIT);
    newRows.add(event.seq);
    if (!paused && !editing()) render();
    else { pending++; jump.textContent = `↑ ${pending} new`; jump.hidden = false; }
  });
  on('world_error', ({ error }) => { loss.textContent = `Events are unavailable: ${error}`; loss.hidden = false; });
  on('error', ({ error }) => { loss.textContent = error; loss.hidden = false; });
  on('open', () => { if (loss.textContent.startsWith('Connection dropped')) { loss.textContent = ''; loss.hidden = true; } });
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
  if (services.labelState) cleanup.push(services.state(services.labelState, (value) => { labels = value.value || []; if (!editing()) render(); }));
  if (services.onMoment) cleanup.push(services.onMoment(() => { if (!paused && !editing()) render(); }));
  render();
  return () => {
    cleanup.forEach((remove) => remove());
    source.close();
    root.replaceChildren();
  };
}
