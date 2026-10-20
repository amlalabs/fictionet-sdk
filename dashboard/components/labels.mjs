import { scoped, icon } from '../dom.mjs';
import { fmtRunTime } from '../format.mjs';

export function labelAction(parent, services, target, title = 'Label', onClose = () => {}) {
  if (!services.labelCommand) return;
  const { el } = scoped(parent);
  const row = el('div', { class: 'label-action' }, parent);
  const open = el('button', { class: 'button', type: 'button', text: title }, row);
  const form = el('form', { hidden: '' }, row);
  const input = el('input', { class: 'text-field', maxlength: '80', 'aria-label': `${title} text`, required: '' }, form);
  const save = el('button', { class: 'button', type: 'submit', text: 'Save' }, form);
  const cancel = el('button', { class: 'button', type: 'button', text: 'Cancel' }, form);
  const status = el('span', { class: 'label-status', role: 'status' }, row);
  form.hidden = true;
  const close = () => { form.hidden = true; open.hidden = false; open.focus(); onClose(); };
  cancel.addEventListener('click', close);
  form.addEventListener('keydown', (event) => { if (event.key === 'Escape') { event.preventDefault(); close(); } });
  open.addEventListener('click', () => { open.hidden = true; form.hidden = false; status.textContent = ''; input.focus(); });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (save.disabled) return;
    save.disabled = true;
    try {
      const result = await services.transport.post(services.labelCommand, { request_id: crypto.randomUUID(), command: { action: 'add', target, text: input.value } });
      status.textContent = result.status === 'applied' ? 'Label added.' : 'Pending. Check Labels and export before trying again.';
      if (result.status === 'applied') close();
    } catch (error) { status.textContent = `Label not confirmed: ${error.message}`; }
    finally { save.disabled = false; }
  });
}

export function mount(root, services, options) {
  const { el } = scoped(root);
  el('h3', { class: 'labels-heading', text: 'Export' }, root);
  const downloads = el('div', { class: 'label-downloads' }, root);
  const scope = el('p', {}, downloads);
  const status = el('p', { role: 'status' }, downloads);
  const stopSelection = services.selection.subscribe(({ host }) => { scope.textContent = host || 'All hosts'; });
  for (const [kind, title] of [['events', 'Events (JSONL)'], ['packets', 'Packets (pcapng)']]) {
    const button = el('button', { class: 'button', type: 'button', text: title }, downloads);
    icon(button, 'download');
    el('p', { class: 'egress-muted', text: kind === 'events' ? 'Events: every event this page holds for the scope, with its labels, as JSONL.' : 'Packets: every captured link in the scope, with the run’s TLS keys, as pcapng.' }, downloads);
    button.addEventListener('click', async () => {
      if (button.disabled) return;
      button.disabled = true;
      status.textContent = 'Preparing download…';
      try {
        await services.transport.download(kind, services.selection.get().host || '');
        status.textContent = 'Download saved.';
      } catch (error) { status.textContent = `Download failed: ${error.message}`; }
      finally { button.disabled = false; }
    });
  }
  const heading = el('h3', { class: 'labels-heading', text: 'Labels (0)' }, root);
  const body = el('div', { class: 'table-scroll labels-table' }, root);
  const { state } = services.graph;
  let snapshot;
  // A label names its target from the graph: redraw as the graph changes.
  const stopGraph = services.graph.subscribe((name) => {
    if (['snapshot', 'event', 'node', 'node_end', 'edge', 'edge_end'].includes(name)) draw();
  });
  function targetText(target) {
    if (target.kind === 'event') {
      const event = state.events.find((event) => event.seq === target.seq);
      return `Event ${target.seq}${event ? ` · ${event.source}.${event.kind} ${event.summary || ''}` : ''}`;
    }
    if (target.kind === 'connection') return `${target.local} ↔ ${target.peer}`;
    const edge = state.edges.get(target.link);
    const node = edge && [state.nodes.get(edge.a), state.nodes.get(edge.b)].find((node) => node?.kind === 'sandbox');
    const host = services.hostLabel(node?.name);
    return `${host ? `${host}'s link` : `Link ${target.link}`} · ${target.a} ↔ ${target.b}`;
  }
  function selectTarget(target) {
    if (target.kind === 'flow') {
      services.selection.set({ host: null, links: [target.link], event: null, connection: null });
      services.showPackets({ local: target.a, peer: target.b });
    } else {
      const event = state.events.find((event) => target.kind === 'event' ? event.seq === target.seq : event.conn === target.id);
      services.selection.set({ host: null, links: [], event: target.kind === 'event' ? event || { seq: target.seq } : null, connection: target.kind === 'connection' ? target.id : event?.conn ?? null, request: null });
      services.showPanel('events');
    }
  }
  let stopState = () => {};
  if (!options.state) el('p', { class: 'empty-note', text: 'This world has not enabled labeling. Run exports are available above.' }, body);
  else stopState = services.state(options.state, (value) => { snapshot = value; draw(); }, (error) => {
    status.textContent = services.stopped() ? 'The run has stopped, so labels can no longer be loaded.' : `Could not load labels: ${error.message}`;
  });
  function draw() {
    if (!snapshot) return;
    heading.textContent = `Labels (${snapshot.value?.length || 0})`;
    body.replaceChildren();
    if (snapshot.status?.too_large) status.textContent = 'Label state exceeded its size limit. The last complete labels are shown.';
    const table = el('table', { class: 'data-table' }, body);
    const head = el('tr', {}, el('thead', {}, table));
    for (const text of ['Label', 'Target', 'Applied', '']) el('th', { text, scope: 'col' }, head);
    const rows = el('tbody', {}, table);
    for (const label of snapshot.value || []) {
      const row = el('tr', {}, rows);
      el('td', { text: label.text }, row);
      const target = el('button', { class: 'text-button label-target', type: 'button', text: targetText(label.target) }, el('td', {}, row));
      target.addEventListener('click', () => selectTarget(label.target));
      el('td', { class: 'numeric', text: fmtRunTime(label.at) }, row);
      const remove = el('button', { class: 'icon-button label-remove', type: 'button', 'aria-label': `Remove label ${label.text}` }, el('td', {}, row));
      icon(remove, 'close');
      remove.addEventListener('click', async () => {
        if (remove.disabled) return;
        remove.disabled = true;
        try {
          const reply = await services.transport.post(options.command, { request_id: crypto.randomUUID(), command: { action: 'remove', id: label.id } });
          status.textContent = reply.status === 'applied' ? 'Label removed.' : 'Removal pending. Read the labels before trying again.';
        } catch (error) { status.textContent = `Removal not confirmed: ${error.message}`; }
        finally { remove.disabled = false; }
      });
    }
    if (!snapshot.value?.length) el('p', { class: 'empty-note', text: 'Select an event, connection or packet flow and choose Label.' }, body);
  }
  return () => { stopState(); stopSelection(); stopGraph(); root.replaceChildren(); };
}
