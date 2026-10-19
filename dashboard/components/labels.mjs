import { scoped } from '../dom.mjs';

export function labelAction(parent, services, target, title = 'Label') {
  if (!services.labelCommand) return;
  const { el } = scoped(parent);
  const row = el('div', { class: 'label-action' }, parent);
  const open = el('button', { class: 'button', type: 'button', text: title }, row);
  const form = el('form', { hidden: '' }, row);
  const input = el('input', { class: 'text-field', maxlength: '80', 'aria-label': `${title} text`, required: '' }, form);
  const save = el('button', { class: 'button', type: 'submit', text: 'Save' }, form);
  const status = el('span', { role: 'status' }, row);
  open.addEventListener('click', () => { form.hidden = false; input.focus(); });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (save.disabled) return;
    save.disabled = true;
    try {
      const result = await services.transport.post(services.labelCommand, { request_id: crypto.randomUUID(), command: { action: 'add', target, text: input.value } });
      status.textContent = result.status === 'applied' ? 'Label added.' : 'Pending. Check Labels and export before trying again.';
      if (result.status === 'applied') form.hidden = true;
    } catch (error) { status.textContent = `Label not confirmed: ${error.message}`; }
    finally { save.disabled = false; }
  });
}

const targetText = (target) => target.kind === 'event' ? `Event ${target.seq}` : target.kind === 'connection'
  ? `Connection ${target.id}: ${target.local} ↔ ${target.peer}` : `${target.link}: ${target.a} ↔ ${target.b}`;

export function mount(root, services, options) {
  const { el } = scoped(root);
  const downloads = el('div', { class: 'label-downloads' }, root);
  const scope = el('p', {}, downloads);
  const status = el('p', { role: 'status' }, downloads);
  const stopSelection = services.selection.subscribe(({ host }) => { scope.textContent = `Export scope: ${host || 'All hosts'}`; });
  for (const [kind, title] of [['events', 'Events (JSONL)'], ['packets', 'Packets (pcapng)']]) {
    const button = el('button', { class: 'button', type: 'button', text: title }, downloads);
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
  const body = el('div', { class: 'table-scroll' }, root);
  let stopState = () => {};
  if (!options.state) el('p', { class: 'empty-note', text: 'This world has not enabled labeling. Run exports are available above.' }, body);
  else stopState = services.state(options.state, (snapshot) => {
    body.replaceChildren();
    if (snapshot.status?.too_large) status.textContent = 'Label state exceeded its size limit. The last complete labels are shown.';
    const table = el('table', { class: 'data-table' }, body);
    const head = el('tr', {}, el('thead', {}, table));
    for (const text of ['Label', 'Target', 'Applied', '']) el('th', { text, scope: 'col' }, head);
    const rows = el('tbody', {}, table);
    for (const label of snapshot.value || []) {
      const row = el('tr', {}, rows);
      el('td', { text: label.text }, row);
      el('td', { class: 'mono', text: targetText(label.target) }, row);
      el('td', { class: 'numeric', text: `${Number(label.at.toFixed(3))} s` }, row);
      const remove = el('button', { class: 'button', type: 'button', text: 'Remove', 'aria-label': `Remove ${label.text}` }, el('td', {}, row));
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
  }, (error) => { status.textContent = `Could not load labels: ${error.message}`; });
  return () => { stopState(); stopSelection(); root.replaceChildren(); };
}
