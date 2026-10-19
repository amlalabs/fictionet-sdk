// mount(root, services, options) returns dispose. Services provide transport and selection.
import { scoped, listen } from '../dom.mjs';

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
      el('time', { text: `${n.at.toFixed(1)}s` }, li);
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


export function mount(root, services, options = {}) {
  const { el } = scoped(root);
  const filter = el('input', { type: 'search', 'aria-label': 'Filter events', placeholder: 'Filter events' }, root);
  const loss = el('p', { role: 'status' }, root);
  const jump = el('button', { type: 'button', hidden: '' }, root);
  const list = el('div', { class: 'event-list' }, root);
  let events = [];
  let host = services.selection.get().host;
  let pending = 0;
  const newRows = new Set();
  let paused = false;
  const source = services.transport.watch();
  const cleanup = [];
  const on = (name, callback) => cleanup.push(listen(source, name, (event) => callback(JSON.parse(event.data))));
  const state = { nodes: new Map() };
  function select(event) {
    const host = services.hosts?.find((host) => host.sandbox === event.sandbox?.name || host.name === event.sandbox?.name)?.name || null;
    services.selection.set({ host, node: event.node || null, event, connection: event.conn ?? null, request: event.fields?.request_id ?? null, links: [] });
  }
  function render() {
    const query = filter.value.trim().toLowerCase();
    const sandbox = services.hosts?.find((item) => item.name === host)?.sandbox || host;
    const visible = events.filter((event) => (!sandbox || event.sandbox?.name === sandbox) && JSON.stringify(event).toLowerCase().includes(query));
    const top = list.scrollTop;
    list.replaceChildren();
    renderEvents(list, visible, { el, state, drawnSource: () => null, tone: () => '', focusNode: (id) => services.selection.set({ node: id }), select: ({ event }) => select(event), onEvent: select, isMoment: services.isMoment, newRows, limit: 500 });
    list.scrollTop = paused ? top : 0;
    newRows.clear();
    pending = 0;
    jump.hidden = true;
  }
  function status(value) {
    const losses = (value?.losses || []).filter((loss) => loss.stream === 'events' || loss.stream === 'topology');
    loss.textContent = losses.map((item) => `${item.stream}: ${item.count} lost (${item.reason}).`).join(' ');
    if (!loss.textContent && value?.incomplete) loss.textContent = 'The observation is incomplete.';
  }
  on('snapshot', (snapshot) => {
    events = snapshot.events.slice(-500);
    state.nodes = new Map(snapshot.nodes.map((node) => [node.id, node]));
    status(snapshot.status);
    render();
  });
  on('node', (node) => state.nodes.set(node.id, node));
  on('node_end', ({ id }) => state.nodes.delete(id));
  on('status', ({ status: value }) => status(value));
  on('event', (event) => {
    events.push(event);
    newRows.add(event.seq);
    if (newRows.size > 500) newRows.delete(newRows.values().next().value);
    events = events.slice(-500);
    if (event.source === 'events' && event.kind === 'dropped') loss.textContent = `${event.fields.count} events lost from history.`;
    if (!paused) render();
    else { pending++; jump.textContent = `${pending} new`; jump.hidden = false; }
  });
  on('world_error', ({ error }) => { loss.textContent = `Events are unavailable: ${error}`; });
  on('error', ({ error }) => { loss.textContent = error; });
  cleanup.push(listen(filter, 'input', render));
  cleanup.push(listen(list, 'scroll', () => { paused = list.scrollTop > 24; }));
  cleanup.push(listen(jump, 'click', () => { paused = false; render(); }));
  cleanup.push(services.selection.subscribe((selection) => {
    if (host !== selection.host) { host = selection.host; render(); }
  }));
  if (services.onMoment) cleanup.push(services.onMoment(() => { if (!paused) render(); }));
  render();
  return () => {
    cleanup.forEach((remove) => remove());
    source.close();
    root.replaceChildren();
  };
}
