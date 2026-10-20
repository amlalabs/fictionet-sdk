// mount(root, services, options) returns dispose. Services provide transport and selection.
// World events the page declared, filtered on the server, as a table. New rows
// arrive at the bottom; reading further up holds the view still.
import { scoped, listen } from '../dom.mjs';
import { render } from './table.mjs';

export function mount(root, services, options) {
  const { el } = scoped(root);
  const status = el('p', { class: 'loss-note', role: 'status', text: 'Loading…' }, root);
  const wrap = el('div', { class: 'list-wrap' }, root);
  const body = el('div', { class: 'table-scroll' }, wrap);
  const jump = el('button', { class: 'jump', type: 'button', hidden: '' }, wrap);
  const controller = new AbortController();
  const schedule = services.setTimeout || setTimeout;
  const cancel = services.clearTimeout || clearTimeout;
  let timer, after = 0, rows = [], pending = 0, paused = false, dropped = 0;
  function draw() {
    render(body, rows, options.columns, { key: (row) => row.seq });
    pending = 0;
    jump.hidden = true;
  }
  async function read() {
    try {
      const reply = await services.transport.get(options.events, { after }, controller.signal);
      if (controller.signal.aborted) return;
      after = reply.next;
      rows = [...rows, ...reply.rows].slice(-1000);
      dropped = reply.dropped || dropped;
      status.textContent = dropped ? `${dropped} events were lost from the history before this table read them.` : '';
      status.hidden = !status.textContent;
      if (paused && reply.rows.length) { pending += reply.rows.length; jump.textContent = `↓ ${pending} new`; jump.hidden = false; }
      else if (!paused) { draw(); body.scrollTop = body.scrollHeight; }
    } catch (error) {
      if (controller.signal.aborted) return;
      status.hidden = false;
      // After the run stopped, the page server is gone: stop asking.
      if (services.stopped?.()) { status.textContent = 'The run has stopped, so these events can no longer be loaded.'; return; }
      status.textContent = `Could not load events: ${error.message}`;
    }
    if (!controller.signal.aborted) timer = schedule(read, 1000);
  }
  const scroll = listen(body, 'scroll', () => { paused = body.scrollHeight - body.scrollTop - body.clientHeight > 24; });
  const click = listen(jump, 'click', () => { paused = false; draw(); body.scrollTop = body.scrollHeight; });
  void read();
  return () => { controller.abort(); cancel(timer); scroll(); click(); root.replaceChildren(); };
}
