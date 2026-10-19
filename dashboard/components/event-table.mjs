// mount(root, services, options) returns dispose. Services provide transport and selection.
import { scoped, listen } from '../dom.mjs';
import { render } from './table.mjs';

export function mount(root, services, options) {
  const { el } = scoped(root);
  const status = el('p', { role: 'status', text: 'Loading…' }, root);
  const jump = el('button', { type: 'button', hidden: '' }, root);
  const body = el('div', { class: 'table-scroll' }, root);
  const controller = new AbortController();
  const schedule = services.setTimeout || setTimeout;
  const cancel = services.clearTimeout || clearTimeout;
  let timer, after = 0, rows = [], pending = 0, paused = false;
  function draw() {
    render(body, rows, options.columns);
    pending = 0;
    jump.hidden = true;
  }
  async function read() {
    try {
      const reply = await services.transport.get(options.events, { after }, controller.signal);
      if (controller.signal.aborted) return;
      after = reply.next;
      rows = [...rows, ...reply.rows].slice(-1000);
      status.textContent = reply.dropped ? `${reply.dropped} events lost from history.` : '';
      if (paused && reply.rows.length) { pending += reply.rows.length; jump.textContent = `${pending} new`; jump.hidden = false; }
      else if (!paused) { draw(); body.scrollTop = body.scrollHeight; }
    } catch (error) {
      if (!controller.signal.aborted) status.textContent = `Could not load events: ${error.message}`;
    } finally {
      if (!controller.signal.aborted) timer = schedule(read, 1000);
    }
  }
  const scroll = listen(body, 'scroll', () => { paused = body.scrollHeight - body.scrollTop - body.clientHeight > 24; });
  const click = listen(jump, 'click', () => { paused = false; draw(); body.scrollTop = body.scrollHeight; });
  void read();
  return () => { controller.abort(); cancel(timer); scroll(); click(); root.replaceChildren(); };
}
