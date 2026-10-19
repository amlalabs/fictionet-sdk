// mount(root, services, options) returns dispose. Commands are sent once per input.
import { scoped, listen } from '../dom.mjs';

export function mount(root, services, options) {
  const { el } = scoped(root);
  const state = el('pre', { class: 'control-state' }, root);
  const actions = el('div', { class: 'control-actions' }, root);
  const reply = el('p', { role: 'status' }, root);
  const controller = new AbortController();
  const cleanup = [];
  const buttons = [];
  let revision, busy = false;
  function enabled() { for (const button of buttons) button.disabled = busy || !!options.state && revision === undefined; }
  for (const action of options.actions) {
    const button = el('button', { type: 'button', text: action.label }, actions);
    buttons.push(button);
    cleanup.push(listen(button, 'click', async () => {
      if (button.disabled || controller.signal.aborted) return;
      busy = true;
      enabled();
      reply.textContent = 'Waiting for the world…';
      const command = options.state ? { ...action.command, expected_revision: revision } : action.command;
      try {
        const result = await services.transport.post(options.command, { request_id: crypto.randomUUID(), command }, controller.signal);
        if (!controller.signal.aborted) reply.textContent = result.status === 'pending' ? 'The command is pending. Read the state before trying again.' : `Applied. ${JSON.stringify(result.reply)}`;
      } catch (error) {
        if (!controller.signal.aborted) reply.textContent = error.body?.status === 'timeout'
          ? 'The command timed out. It may still apply. Read the state before trying again.'
          : error.body?.rejection ? `Rejected. ${JSON.stringify(error.body.rejection)}` : `Command failed: ${error.message}`;
      } finally {
        if (!controller.signal.aborted) { busy = false; enabled(); }
      }
    }));
  }
  if (options.state) cleanup.push(services.state(options.state, (snapshot) => {
    revision = snapshot.revision;
    state.textContent = JSON.stringify(snapshot.value, null, 2);
    enabled();
  }, (error) => { revision = undefined; enabled(); reply.textContent = `Could not read state: ${error.message}`; }));
  enabled();
  return () => { controller.abort(); cleanup.forEach((remove) => remove()); root.replaceChildren(); };
}
