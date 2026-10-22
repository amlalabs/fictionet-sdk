import { diff } from './model.mjs';
import { createWeb } from './web.mjs';

const NEW_PAGES = [['copied', 'Copied'], ['model_written', 'Model-written'], ['live_search', 'Live']];
export function mount(root, services, options) {
  services.forwardedHosts.set(new Set(options.forwardedHosts || []));
  const { el } = services.dom.scoped(root);
  const { listen } = services.dom;
  el('link', { rel: 'stylesheet', href: '/assets/search/style.css' }, root);
  root.classList.add('search-world');
  const stage = el('div', { class: 'web-map' }, root);
  const web = createWeb(stage, services);
  const controller = new AbortController();
  const cleanup = [];
  let snapshot = null, disposed = false;
  const menu = services.worldMenu;
  const request = services.command(controller.signal, () => buttons());
  const controls = [];
  let note, segment;
  async function send(command) {
    if (!snapshot || request.busy) return false;
    note.textContent = '';
    let ok = false;
    await request.send('/api/command/generation', command, snapshot.generator.generation_revision, {
      reply(reply) {
        if (reply.status === 'applied') ok = true;
        else note.textContent = reply.status === 'pending' ? 'Pending' : 'Try again';
      },
      error(error) {
        const rejection = error.body?.rejection;
        note.textContent = rejection?.reason === 'stale_revision' ? 'World changed' : 'Request failed';
      },
    });
    return ok;
  }
  let availability;
  function buttons() {
    for (const control of controls) control.disabled = !snapshot || request.busy;
    if (!segment || !snapshot?.generator) return;
    const g = snapshot.generator;
    if (availability) availability.textContent = g.live_available ? '' : 'Live unavailable';
    const mode = g.live_search ? 'live_search' : g.copied ? 'copied' : 'model_written';
    for (const button of segment.children) {
      button.setAttribute('aria-pressed', String(button.dataset.mode === mode));
      if (button.dataset.mode === 'live_search') {
        button.disabled = request.busy || !g.live_available;
        button.title = g.live_available ? '' : 'Live unavailable';
      }
    }
  }
  if (menu) {
    const { el: item } = services.dom.scoped(menu);
    const row = item('div', { class: 'row' }, menu);
    item('span', { text: 'Pages' }, row);
    segment = item('div', { class: 'seg', role: 'group', 'aria-label': 'Pages' }, row);
    for (const [mode, text] of NEW_PAGES) {
      const button = item('button', { type: 'button', text, 'aria-pressed': 'false' }, segment);
      button.dataset.mode = mode;
      controls.push(button);
      cleanup.push(listen(button, 'click', () => send({ command: 'set_new_pages', new_pages: mode })));
    }
    availability = item('p', { class: 'note' }, menu);
    const restartRow = item('div', { class: 'row' }, menu);
    item('span', { text: 'Restart run' }, restartRow);
    const restart = item('button', { type: 'button', class: 'act quiet', text: 'Restart' }, restartRow);
    controls.push(restart);
    cleanup.push(listen(restart, 'click', () => send({ command: 'restart' })));
    note = item('p', { class: 'note', role: 'status' }, menu);
  } else {
    note = el('p', { class: 'note', role: 'status' }, null);
  }
  buttons();
  const graph = services.graph;
  cleanup.push(graph.subscribe((name) => {
    if (name === 'event' || name === 'snapshot') web.setEvents(graph.state.events);
  }));

  cleanup.push(services.state(options.state, ({ value }) => {
    if (disposed || !value) return;
    const names = new Map((value.sites || []).map(({ address, host }) => [address, host]));
    const previousNames = services.endpointNames.get();
    if (names.size !== previousNames.size || [...names].some(([address, host]) => previousNames.get(address) !== host)) services.endpointNames.set(names);
    const changes = diff(snapshot, value);
    const reset = !snapshot || changes.some((change) => change.type === 'restart');
    if (reset) web.reset(value);
    else web.apply(changes, value);
    snapshot = value;
    buttons();
  }, () => { if (!disposed) note.textContent = 'World unavailable'; }));
  return () => {
    disposed = true;
    controller.abort();
    web.dispose();
    cleanup.forEach((off) => off());
    menu?.replaceChildren();
    root.classList.remove('search-world');
    root.replaceChildren();
  };
}
