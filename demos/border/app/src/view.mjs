// The world pane: the route from the workstation through the networks to
// the bank or the impostor, above the newest rows of what crossed it. When
// the password reaches the impostor, the impostor and its row flash red.
// The World menu (services.worldMenu) sets the route and the impostor and
// restarts the run.
import { route, stolen, rows, clock } from './picture.mjs';

// How long a theft flashes, in milliseconds.
const FLASH = 6000;

export function mount(root, services, options) {
  const { el } = services.dom.scoped(root);
  const { listen, reconcile } = services.dom;
  el('link', { rel: 'stylesheet', href: '/assets/border/style.css' }, root);
  root.classList.add('border-world');
  const svg = el('svg:svg', { class: 'border-picture', viewBox: '0 0 520 440', role: 'img', 'aria-label': 'Route from the workstation to the bank' }, root);
  // Each part keeps its own classes; a draw adds one state to them.
  const base = new Map();
  const add = (tag, attrs, text) => {
    const node = el(`svg:${tag}`, attrs, svg);
    if (text != null) node.textContent = text;
    base.set(node, attrs.class || '');
    return node;
  };
  const set = (part, tone) => part.setAttribute('class', `${base.get(part)}${tone ? ` ${tone}` : ''}`);
  // Lines first, so nodes sit on top of them.
  const line = (x1, y1, x2, y2) => add('line', { class: 'edge', x1, y1, x2, y2 });
  const lines = {
    gateway: line(94, 90, 179, 90),
    home: line(201, 90, 299, 90),
    bank: line(321, 90, 429, 90),
    border: line(310, 101, 310, 219),
    impostor: line(319, 237, 427, 320),
  };
  const token = add('g', { class: 'token' });
  el('svg:circle', { cx: 380, cy: 284, r: 6 }, token);
  el('svg:text', { x: 392, y: 276, text: 'password' }, token);
  for (const r of [46, 30]) add('circle', { class: 'pulse', cx: 440, cy: 330, r });
  add('rect', { class: 'node on', x: 46, y: 72, width: 48, height: 36, rx: 6 });
  add('text', { class: 'label', x: 70, y: 132, 'text-anchor': 'middle' }, 'workstation');
  const node = (cx, cy, r, label, lx, ly, anchor = 'middle', big = false) => ({
    circle: add('circle', { class: `node${big ? ' impostor' : ''}`, cx, cy, r }),
    label: add('text', { class: `label${big ? ' big' : ''}`, x: lx, y: ly, 'text-anchor': anchor }, label),
  });
  const nodes = {
    gateway: node(190, 90, 11, 'gateway', 190, 124),
    home: node(310, 90, 11, 'Harbourline', 310, 62),
    bank: node(440, 90, 11, 'Kestrelmoor', 440, 124),
    foreign: node(310, 230, 11, 'Transpeak', 290, 234, 'end'),
    impostor: node(440, 330, 15, 'impostor', 440, 378, 'middle', true),
  };
  const list = el('div', { class: 'border-rows', role: 'list', 'aria-label': 'What crossed the route' }, root);
  const retained = new Map();

  const controller = new AbortController();
  const cleanup = [];
  let state = null, view = null, seen, flashUntil = 0, flashTimer = 0, disposed = false;
  const menu = services.worldMenu;
  const request = services.command(controller.signal, () => buttons());
  const controls = [];
  let note, routeSeg, impostorSeg;
  async function send(command) {
    if (!state || request.busy) return;
    note.textContent = '';
    await request.send('/api/command/world', command, state.revision, {
      reply(reply) {
        if (reply.status !== 'applied') note.textContent = reply.status === 'pending' ? 'The world has not answered yet.' : reply.rejection?.message || 'Not applied.';
      },
      error(error) {
        const rejection = error.body?.rejection;
        note.textContent = rejection?.reason === 'stale_revision' ? 'The world changed. Try again.' : rejection?.message || error.message;
      },
    });
  }
  function seg(parent, label, choices, command) {
    const group = services.dom.scoped(parent).el('div', { class: 'seg', role: 'group', 'aria-label': label }, parent);
    for (const [value, text] of choices) {
      const button = services.dom.scoped(parent).el('button', { type: 'button', text, 'aria-pressed': 'false' }, group);
      button.dataset.value = value;
      controls.push(button);
      cleanup.push(listen(button, 'click', () => {
        if (button.getAttribute('aria-pressed') !== 'true') send(command(value));
      }));
    }
    return group;
  }
  if (menu) {
    const { el: item } = services.dom.scoped(menu);
    menu.replaceChildren();
    const routeRow = item('div', { class: 'row' }, menu);
    item('span', { text: 'Route' }, routeRow);
    routeSeg = seg(routeRow, 'Route', [['legitimate', 'Normal'], ['hijack', 'Hijacked']], (mode) => ({ command: 'route', mode }));
    const impostorRow = item('div', { class: 'row' }, menu);
    item('span', { text: 'Impostor' }, impostorRow);
    impostorSeg = seg(impostorRow, 'Impostor', [['on', 'On'], ['off', 'Off']], (value) => ({ command: 'impostor', on: value === 'on' }));
    const restartRow = item('div', { class: 'row' }, menu);
    item('span', { text: 'Restart run' }, restartRow);
    const restart = item('button', { type: 'button', class: 'act quiet', text: 'Restart' }, restartRow);
    controls.push(restart);
    cleanup.push(listen(restart, 'click', () => send({ command: 'restart' })));
    note = item('p', { class: 'note', role: 'status' }, menu);
  } else {
    note = el('p', { class: 'note', role: 'status' }, null);
  }

  function buttons() {
    for (const control of controls) control.disabled = !state || request.busy;
    const now = route(state);
    const press = (group, value) => {
      for (const button of group?.children || []) button.setAttribute('aria-pressed', String(Boolean(state) && button.dataset.value === value));
    };
    press(routeSeg, now.hijacked ? 'hijack' : 'legitimate');
    press(impostorSeg, now.impostor ? 'on' : 'off');
  }

  function draw() {
    const now = route(state);
    const theft = stolen(view);
    if (view && seen === undefined) seen = theft?.event ?? null;
    if (theft && theft.event !== seen) {
      seen = theft.event;
      flashUntil = Date.now() + FLASH;
      clearTimeout(flashTimer);
      flashTimer = setTimeout(draw, FLASH);
    }
    const flashing = Date.now() < flashUntil;
    root.dataset.mode = now.hijacked ? 'hijack' : 'normal';
    root.dataset.impostor = now.impostor ? 'on' : 'off';
    root.classList.toggle('flash', flashing);
    set(lines.bank, now.hijacked ? 'idle' : 'on');
    set(lines.border, now.hijacked ? 'bad' : 'idle');
    set(lines.impostor, now.hijacked ? (now.impostor ? 'bad' : 'bad off') : 'idle');
    for (const part of [lines.gateway, lines.home]) set(part, 'on');
    const tone = (name, value) => { set(nodes[name].circle, value); set(nodes[name].label, value); };
    tone('gateway', 'on');
    tone('home', 'on');
    tone('bank', now.hijacked ? 'idle' : 'on');
    tone('foreign', now.hijacked ? 'bad' : 'idle');
    tone('impostor', theft ? 'hot' : !now.impostor ? 'off' : now.hijacked ? 'bad' : 'idle');
    set(token, theft ? 'shown' : '');
    reconcile(list, rows(view), (r) => r.id, () => {
      const line = el('div', { class: 'border-row', role: 'listitem' }, null);
      return { node: line, time: el('time', {}, line), who: el('span', {}, line), what: el('b', {}, line) };
    }, (entry, r) => {
      entry.node.className = `border-row${r.tone ? ` ${r.tone}` : ''}${flashing && r.id === seen ? ' flash' : ''}`;
      entry.time.textContent = clock(r.at);
      entry.who.textContent = r.who;
      entry.who.title = r.who;
      entry.what.textContent = r.what;
      entry.what.title = r.what;
    }, retained);
    buttons();
  }
  draw();
  const failed = (error) => { if (!disposed) note.textContent = error.message; };
  cleanup.push(services.state('/api/state/routing', ({ value }) => {
    if (disposed || !value) return;
    state = value;
    draw();
  }, failed));
  cleanup.push(services.state(options.state, ({ value }) => {
    if (disposed || !value) return;
    view = value;
    draw();
  }, failed));
  return () => {
    disposed = true;
    controller.abort();
    clearTimeout(flashTimer);
    cleanup.forEach((off) => off());
    menu?.replaceChildren();
    root.classList.remove('border-world', 'flash');
    root.replaceChildren();
  };
}
