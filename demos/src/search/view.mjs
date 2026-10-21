// The world pane: the newest search, the engines that answered it and the
// sites its list named, above the newest rows of what the world served. The
// World menu (services.worldMenu, when the page is an app) chooses what
// answers, plants a fact or a page, and restarts the run.
import { picture, rows } from './model.mjs';

const NEW_PAGES = [['canned', 'Prepared'], ['stub', 'Improvised'], ['off', 'Off']];
// Run time as minutes and seconds.
const clock = (ms) => { const s = Math.floor(ms / 1000); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };

export function mount(root, services, options) {
  const { el } = services.dom.scoped(root);
  const { listen } = services.dom;
  el('link', { rel: 'stylesheet', href: '/assets/search/style.css' }, root);
  root.classList.add('search-world');
  const svg = el('svg:svg', { class: 'search-picture', viewBox: '0 0 520 440', role: 'img', 'aria-label': 'Searches and the sites they named' }, root);
  const list = el('div', { class: 'search-rows', role: 'list', 'aria-label': 'What the world served' }, root);
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
        else note.textContent = reply.status === 'pending' ? 'The world has not answered yet.' : reply.rejection?.message || 'Not applied.';
      },
      error(error) {
        const rejection = error.body?.rejection;
        note.textContent = rejection?.reason === 'stale_revision' ? 'The world changed. Try again.' : rejection?.message || error.message;
      },
    });
    return ok;
  }
  function buttons() {
    for (const control of controls) control.disabled = !snapshot || request.busy;
    if (!segment || !snapshot) return;
    const g = snapshot.generator;
    const mode = !g.generate ? 'off' : g.canned ? 'canned' : 'stub';
    for (const button of segment.children) button.setAttribute('aria-pressed', String(button.dataset.mode === mode));
  }
  if (menu) {
    const { el: item } = services.dom.scoped(menu);
    menu.replaceChildren();
    const row = item('div', { class: 'row' }, menu);
    item('span', { text: 'New pages' }, row);
    segment = item('div', { class: 'seg', role: 'group', 'aria-label': 'New pages' }, row);
    for (const [mode, text] of NEW_PAGES) {
      const button = item('button', { type: 'button', text, 'aria-pressed': 'false' }, segment);
      button.dataset.mode = mode;
      controls.push(button);
      cleanup.push(listen(button, 'click', () => send({ command: 'set_new_pages', new_pages: mode })));
    }
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

  function draw() {
    const view = picture(snapshot);
    svg.replaceChildren();
    const add = (tag, attrs, text) => {
      const node = el(`svg:${tag}`, attrs, svg);
      if (text != null) node.textContent = text;
      return node;
    };
    const ex = [110, 260, 410], ey = 134;
    add('rect', { class: 'query', x: 60, y: 22, width: 400, height: 32, rx: 16 });
    const words = view.query || 'Waiting for a search';
    add('text', { class: `query-text${view.query ? '' : ' idle'}`, x: 260, y: 43, 'text-anchor': 'middle' }, words.length > 52 ? `${words.slice(0, 51)}…` : words);
    view.engines.forEach((e, i) => {
      add('line', { class: `edge${e.tag === 'idle' ? ' idle' : ''}`, x1: 260, y1: 54, x2: ex[i], y2: ey - 12 });
    });
    // Engines that showed the same list share it.
    const shown = view.engines.map((e, i) => [e, i]).filter(([e]) => e.tag !== 'idle');
    for (let n = 1; n < shown.length; n++) {
      if (shown[n][0].tag === 'memory' || shown[n][0].tag === 'canned') {
        add('line', { class: 'edge shared', x1: ex[shown[n - 1][1]] + 14, y1: ey, x2: ex[shown[n][1]] - 14, y2: ey });
      }
    }
    const spots = [[90, 252], [210, 262], [330, 252], [450, 262], [150, 334], [390, 334]];
    view.sites.forEach((site, n) => {
      const [x, y] = spots[n];
      view.engines.forEach((e, i) => { if (e.tag !== 'idle') add('line', { class: 'edge thin', x1: ex[i], y1: ey + 12, x2: x, y2: y - 10 }); });
    });
    view.engines.forEach((e, i) => {
      add('circle', { class: `node ${e.tag}`, cx: ex[i], cy: ey, r: 12 });
      add('text', { class: 'label', x: ex[i], y: ey - 22, 'text-anchor': 'middle' }, e.label);
    });
    view.sites.forEach((site, n) => {
      const [x, y] = spots[n];
      const r = site.pages ? Math.min(16, 8 + 3 * site.pages) : 7;
      add('circle', { class: `node site ${site.pages ? site.tag : 'listed'}${site.seed ? ' seed' : ''}`, cx: x, cy: y, r });
      add('text', { class: 'label small', x, y: y + r + 16, 'text-anchor': 'middle' }, site.label).append(el('svg:title', { text: site.host }, null));
      if (site.pages) add('text', { class: 'label small muted', x, y: y + r + 30, 'text-anchor': 'middle' }, `${site.pages} ${site.pages === 1 ? 'page' : 'pages'}`);
    });
    if (view.more) add('text', { class: 'label small muted', x: 490, y: 300, 'text-anchor': 'end' }, `+${view.more}`);
    view.planted.forEach((p, n) => {
      const x = 250 + n * 135;
      add('circle', { class: 'node planted', cx: x, cy: 404, r: 9 });
      const label = p.label.length > 14 ? `${p.label.slice(0, 13)}…` : p.label;
      add('text', { class: 'label small', x: x + 16, y: 408 }, label).append(el('svg:title', { text: p.text }, null));
    });
    if (view.refused) {
      add('circle', { class: 'node refused', cx: 40, cy: 404, r: 11 });
      add('line', { class: 'cross', x1: 33, y1: 397, x2: 47, y2: 411 });
      add('line', { class: 'cross', x1: 47, y1: 397, x2: 33, y2: 411 });
      const name = view.refused.length > 22 ? `${view.refused.slice(0, 21)}…` : view.refused;
      add('text', { class: 'label refused', x: 60, y: 409 }, name);
    }
  }
  function render() {
    draw();
    list.replaceChildren();
    for (const row of rows(snapshot)) {
      const line = el('div', { class: 'search-row', role: 'listitem' }, list);
      el('time', { text: clock(row.at) }, line);
      el('span', { text: row.who, title: row.who }, line);
      el('b', { text: row.what, title: row.what }, line);
      const badge = ({ canned: '', made: 'made now', memory: 'again' })[row.tag] ?? row.tag;
      if (badge) el('em', { class: row.tag, text: badge }, line);
    }
    buttons();
  }
  cleanup.push(services.state(options.state, ({ value }) => {
    if (disposed || !value) return;
    snapshot = value;
    render();
  }, (error) => { if (!disposed) note.textContent = error.message; }));
  return () => {
    disposed = true;
    controller.abort();
    cleanup.forEach((off) => off());
    menu?.replaceChildren();
    root.classList.remove('search-world');
    root.replaceChildren();
  };
}
