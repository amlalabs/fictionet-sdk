// mount(root, services, options) returns dispose. Commands are sent once per input.
// A control's actions post the world's own command type. With a linked state
// topic, the panel sends the value's revision, or the envelope revision when
// absent, so the world can refuse a command made against an old state.
import { scoped, listen } from '../dom.mjs';
import { fmtDuration } from '../format.mjs';

const humanize = (key) => {
  const words = String(key).replace(/[_-]+/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').trim().toLowerCase();
  return words ? words[0].toUpperCase() + words.slice(1) : String(key);
};
const text = (value) => (value !== null && typeof value === 'object' ? JSON.stringify(value) : String(value));

/// A value as a key and value list: one row per field of an object.
function keyValues(parent, el, value) {
  const dl = el('dl', { class: 'kv' }, parent);
  const entries = value !== null && typeof value === 'object' && !Array.isArray(value) ? Object.entries(value) : [['Value', value]];
  for (const [key, item] of entries) {
    el('dt', { text: humanize(key) }, dl);
    el('dd', { text: text(item) }, dl);
  }
  return dl;
}

/// What a refusal means, in words.
export function rejection(rejected) {
  switch (rejected?.reason) {
    case 'stale_revision': return `Not applied: the state changed (now revision ${rejected.current}). Check it and try again.`;
    case 'invalid': return `Not applied: ${rejected.message}`;
    case 'unavailable': return 'Not applied: the world is not taking commands right now.';
    default: return `Not applied: ${text(rejected)}`;
  }
}

export function mount(root, services, options) {
  const { el } = scoped(root);
  const state = el('div', { class: 'control-state' }, root);
  const actions = el('div', { class: 'control-actions' }, root);
  const reply = el('div', { class: 'control-reply', role: 'status' }, root);
  const controller = new AbortController();
  const cleanup = [];
  const buttons = [];
  let revision, busy = false;
  const when = () => (services.runTime ? ` at ${fmtDuration(services.runTime())}` : '');
  function say(line, value) {
    reply.replaceChildren();
    el('p', { text: line }, reply);
    if (value !== undefined && value !== null) keyValues(reply, el, value);
  }
  function enabled() { for (const button of buttons) button.disabled = busy || (!!options.state && revision === undefined); }
  for (const action of options.actions) {
    const button = el('button', { class: 'button', type: 'button', text: action.label }, actions);
    buttons.push(button);
    cleanup.push(listen(button, 'click', async () => {
      if (button.disabled || controller.signal.aborted) return;
      busy = true;
      enabled();
      say('Waiting for the world…');
      const command = options.state ? { ...action.command, expected_revision: revision } : action.command;
      try {
        const result = await services.transport.post(options.command, { request_id: crypto.randomUUID(), command }, controller.signal);
        if (controller.signal.aborted) return;
        if (result.status === 'pending') say(`Pending${when()}. Read the state before trying again.`);
        else say(`${action.label}: applied${when()}`, result.reply);
      } catch (error) {
        if (controller.signal.aborted) return;
        if (error.body?.status === 'timeout') say(`${action.label}: no reply yet${when()}. It may still apply. Read the state before trying again.`);
        else if (error.body?.rejection) say(`${action.label}${when()}. ${rejection(error.body.rejection)}`);
        else say(`${action.label}: the command failed: ${error.message}`);
      } finally {
        if (!controller.signal.aborted) { busy = false; enabled(); }
      }
    }));
  }
  if (options.state) {
    cleanup.push(services.state(options.state, (snapshot) => {
      revision = snapshot.value?.revision ?? snapshot.revision;
      state.replaceChildren();
      if (snapshot.value === null || snapshot.value === undefined) el('p', { class: 'empty-note', text: 'The world has not published this state yet.' }, state);
      else keyValues(state, el, snapshot.value);
      enabled();
    }, (error) => { revision = undefined; enabled(); say(`Could not read the state: ${error.message}`); }));
  } else state.hidden = true;
  enabled();
  return () => { controller.abort(); cleanup.forEach((remove) => remove()); root.replaceChildren(); };
}
