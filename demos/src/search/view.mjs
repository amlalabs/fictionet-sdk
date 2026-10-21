import { diff, rows } from './model.mjs';
import { createMotion } from './motion.mjs';
import { createWeb } from './web.mjs';

const DESCRIPTIONS = { canned: 'Prepared pages answer first; the rest are made on the spot.', stub: 'New pages are made on the spot.', off: 'Only available pages are served.' };
const NEW_PAGES = [['canned', 'Prepared'], ['stub', 'Improvised'], ['off', 'Off']];
// Run time as minutes and seconds.
const clock = (ms) => { const s = Math.floor(ms / 1000); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };

export function mount(root, services, options) {
  const { el } = services.dom.scoped(root);
  const { listen } = services.dom;
  el('link', { rel: 'stylesheet', href: '/assets/search/style.css' }, root);
  root.classList.add('search-world');
  const svg = el('svg:svg', { class: 'search-picture', viewBox: '0 0 520 560', role: 'img', 'aria-label': 'Searches and the sites they named' }, root);
  const list = el('div', { class: 'search-rows', role: 'list', 'aria-label': 'What the world served' }, root);
  const motion = createMotion(root.ownerDocument.defaultView || globalThis);
  const web = createWeb(svg, { el, motion });
  const controller = new AbortController();
  const cleanup = [motion.subscribe((disabled) => root.classList.toggle('no-motion', disabled))];
  const rowNodes = new Map();
  let snapshot = null, disposed = false;
  const menu = services.worldMenu;
  const request = services.command(controller.signal, () => buttons());
  const controls = [];
  let note, segment, description;
  async function send(command) {
    if (!snapshot || request.busy) return false;
    note.textContent = '';
    let ok = false;
    await request.send('/api/command/generation', command, snapshot.generator.generation_revision, {
      reply(reply) {
        if (reply.status === 'applied') ok = true;
        else note.textContent = reply.status === 'pending' ? 'The world has not answered yet.' : 'Check the values and try again.';
      },
      error(error) {
        const rejection = error.body?.rejection;
        note.textContent = rejection?.reason === 'stale_revision' ? 'The world changed. Try again.' : 'The request could not be completed.';
      },
    });
    return ok;
  }
  function buttons() {
    for (const control of controls) control.disabled = !snapshot || request.busy;
    if (!segment || !snapshot?.generator) return;
    const g = snapshot.generator;
    const mode = !g.generate ? 'off' : g.canned ? 'canned' : 'stub';
    description.textContent = DESCRIPTIONS[mode];
    for (const button of segment.children) button.setAttribute('aria-pressed', String(button.dataset.mode === mode));
  }
  if (menu) {
    const { el: item } = services.dom.scoped(menu);
    const row = item('div', { class: 'row' }, menu);
    item('span', { text: 'New pages' }, row);
    segment = item('div', { class: 'seg', role: 'group', 'aria-label': 'New pages' }, row);
    for (const [mode, text] of NEW_PAGES) {
      const button = item('button', { type: 'button', text, 'aria-pressed': 'false' }, segment);
      button.dataset.mode = mode;
      controls.push(button);
      cleanup.push(listen(button, 'click', () => send({ command: 'set_new_pages', new_pages: mode })));
    }
    description = item('p', { class: 'mode-description' }, menu);
    const field = (label, id) => {
      const box = item('div', { class: 'field' }, menu);
      item('label', { for: id, text: label }, box);
      return box;
    };
    const factBox = field('Plant a fact', 'plant-fact');
    const fact = item('input', { id: 'plant-fact', type: 'text', autocomplete: 'off' }, factBox);
    const plantFact = item('button', { type: 'button', class: 'act', text: 'Plant' }, factBox);
    controls.push(plantFact);
    cleanup.push(listen(plantFact, 'click', async () => {
      if (await send({ command: 'plant_fact', text: fact.value })) fact.value = '';
    }));
    const pageBox = field('Plant a page', 'plant-url');
    const url = item('input', { id: 'plant-url', type: 'url', placeholder: 'https://', autocomplete: 'off' }, pageBox);
    const plantPage = item('button', { type: 'button', class: 'act', text: 'Plant' }, pageBox);
    const text = item('textarea', { 'aria-label': 'Page text', placeholder: 'Title, then the text', rows: '3' }, pageBox);
    controls.push(plantPage);
    cleanup.push(listen(plantPage, 'click', async () => {
      if (await send({ command: 'plant_page', url: url.value, text: text.value })) { url.value = ''; text.value = ''; }
    }));
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

  function render(changes = []) {
    const entries = rows(snapshot).map((row) => [JSON.stringify(row), row]);
    const keys = new Set(entries.map(([key]) => key));
    for (const [key, node] of rowNodes) if (!keys.has(key)) { node.remove(); rowNodes.delete(key); }
    entries.forEach(([key, row], index) => {
      let line = rowNodes.get(key);
      if (!line) {
        line = el('div', { class: 'search-row', role: 'listitem', title: `${clock(row.at)} · ${row.who === 'Claude Code' ? '❯ Claude Code' : row.who} · ${row.what}${row.badge ? ` · ${row.badge}` : ''}` }, list);
        rowNodes.set(key, line);
        if (changes.length) motion.anim(line, [{ opacity: 0, transform: 'translateY(-10px)' }, { opacity: 1, transform: 'translateY(0)' }], { duration: 260, easing: 'cubic-bezier(.2,.7,.3,1)' });
        el('time', { text: clock(row.at) }, line);
        el('span', { text: row.who === 'Claude Code' ? '❯ Claude Code' : row.who, title: row.who === 'Claude Code' ? '❯ Claude Code' : row.who }, line);
        const what = el('b', { title: row.what }, line);
        if (row.carries) el('i', { class: 'fact-dot', 'aria-label': 'Carries a planted fact' }, what);
        el('span', { class: 'row-text', text: row.what }, what);
        if (row.badge) el('em', { class: row.tag, text: row.badge }, line);
      }
      if (list.children[index] !== line) list.insertBefore(line, list.children[index] || null);
    });
    buttons();
  }
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
    render(reset ? [] : changes);
  }, () => { if (!disposed) note.textContent = 'The world could not be reached.'; }));
  return () => {
    disposed = true;
    controller.abort();
    web.dispose();
    cleanup.forEach((off) => off());
    menu?.replaceChildren();
    root.classList.remove('search-world');
    root.classList.remove('no-motion');
    root.replaceChildren();
  };
}
