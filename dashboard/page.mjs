// The demo page: a host bar, a workspace of consoles beside a tabbed
// inspector, built from the page description the server gives at /api/page.
// Components share one watch stream and one state stream (see streams.mjs).
import { createTransport, createCommand, SIGN_IN } from './transport.mjs';
import { createSelection } from './selection.mjs';
import { createTheme } from './theme.mjs';
import { createStateHub, createWatchHub } from './streams.mjs';
import { createModel } from './state.mjs';
import * as format from './format.mjs';
import * as dom from './dom.mjs';
import { scoped, listen } from './dom.mjs';
import { mount as screen } from './components/screen.mjs';
import { mount as terminal } from './components/terminal.mjs';
import { mount as packets } from './components/packets.mjs';
import { mount as labels } from './components/labels.mjs';
import { mount as containment } from './components/containment.mjs';
import { mount as leftTheBox } from './components/left-the-box.mjs';
import { mount as events } from './components/events.mjs';
import { mount as map } from './components/map.mjs';
import { mount as table } from './components/table.mjs';
import { mount as eventTable } from './components/event-table.mjs';
import { mount as control } from './components/control.mjs';
import { mount as custom } from './components/custom.mjs';
import { createInputOwners, READINESS } from './components/console.mjs';

// A value components can read and follow.
function store(value) {
  const listeners = new Set();
  return {
    get: () => value,
    set(next) { value = next; listeners.forEach((listener) => listener(value)); },
    subscribe(listener) { listeners.add(listener); listener(value); return () => listeners.delete(listener); },
  };
}

// Lookups over `hosts()`, the page's hosts. `hostOf(name)` is the host whose
// sandbox is `name`, or else the host named `name`, or null. `hostLabel(name)`
// is the same host, or `name` when there is none, for text. `sandboxOf(name)`
// is the sandbox of the host named `name`, or `name` when there is none.
export function hostLookups(hosts) {
  const hostOf = (name) => (hosts().find((host) => host.sandbox === name) || hosts().find((host) => host.name === name))?.name ?? null;
  return {
    hostOf,
    hostLabel: (name) => hostOf(name) ?? name,
    sandboxOf: (name) => hosts().find((host) => host.name === name)?.sandbox ?? name,
  };
}

export function createServices(transport, theme, importModule = (url) => import(url)) {
  // The run status the header shows: connecting, running or stopped.
  const run = store('connecting');
  const stopped = () => run.get() === 'stopped';
  const states = createStateHub(transport, { stopped });
  const watches = createWatchHub(transport);
  let graph;
  const selection = createSelection();
  const packetFilter = store('conversations');
  try {
    if (globalThis.localStorage?.getItem('fictionet-packet-filter') === 'every') packetFilter.set('every');
  } catch { /* Storage may be disabled. */ }
  packetFilter.subscribe((value) => {
    try { globalThis.localStorage?.setItem('fictionet-packet-filter', value); } catch { /* Storage may be disabled. */ }
  });
  const moments = new Set();
  const momentListeners = new Set();
  const clock = { t: 0, at: performance.now(), ended: true };
  const services = {
    transport, selection, theme, format, dom, clock, run, packetFilter, endpointNames: store(new Map()),
    command: (signal, changed) => createCommand(transport, signal, changed),
    // The page's one graph model (see state.mjs), on the page's watch. It
    // binds the first time a part of the page reads it.
    get graph() { graph ??= createModel(watches.subscribe()); return graph; },
    // From /api/page: the page's hosts, the addresses its own screen and
    // terminal sessions come from, and the state and command paths of its
    // labels and startup checks, or null when it has no such panel.
    hosts: [],
    claudeStarted: new Set(),
    labelState: null,
    labelCommand: null,
    containmentState: null,
    ...hostLookups(() => services.hosts),
    // Whether the header says Stopped. A load that fails then says the run
    // stopped, not why the request failed.
    stopped,
    packetPair: store(null),
    // Opens an inspector panel by kind, or by id for panels that share a
    // kind. The inspector sets it once its tabs exist.
    showPanel() {},
    // Shows the packets of a map item's links, or of one flow.
    openLinks(_from, _to, members) { selection.set({ links: members.map(({ e }) => e.id) }); services.showPanel('packets'); },
    showPackets(pair) { services.packetPair.set(pair); services.showPanel('packets'); },
    // Loads a module by URL: a console's library or a world panel. Tests
    // pass their own, since Node cannot load the page's paths.
    importModule,
    // Who holds each host's input (see components/console.mjs).
    input: createInputOwners((path, onSnapshot, onError) => services.state(path, onSnapshot, onError)),
    watch: () => watches.subscribe(),
    state(path, onSnapshot, onError) {
      if (!/^\/api\/state\/[A-Za-z0-9_-]{1,128}$/.test(path)) throw new Error('Invalid state path');
      return states.subscribe(path.slice('/api/state/'.length), onSnapshot, onError);
    },
    runTime: () => clock.t + (clock.ended ? 0 : (performance.now() - clock.at) / 1000),
    moment(element) { element.classList.add('moment'); },
    isMoment: (event) => moments.has(event.seq),
    onMoment(callback) { momentListeners.add(callback); return () => momentListeners.delete(callback); },
    markMoment(event) {
      moments.add(event.seq);
      if (moments.size > 1000) moments.delete(moments.values().next().value);
      momentListeners.forEach((callback) => callback());
    },
    dispose() { graph?.dispose(); states.dispose(); watches.dispose(); momentListeners.clear(); },
  };
  return services;
}

// The workspace's share of the width until the viewer drags the divider.
const DEFAULT_SPLIT = 58;

export function divider(element, workspace, title, initial = DEFAULT_SPLIT) {
  let percent = initial;
  const key = `fictionet-divider:${title}`;
  try { const saved = Number(localStorage.getItem(key)); if (saved >= 25 && saved <= 80) percent = saved; } catch { /* The position still lasts for this page. */ }
  function apply(value, save = true) {
    percent = Math.max(25, Math.min(80, value));
    workspace.style.setProperty('--workspace', `${percent}%`);
    element.setAttribute('aria-valuenow', String(Math.round(percent)));
    if (save) try { localStorage.setItem(key, String(percent)); } catch { /* Storage may be disabled. */ }
  }
  let dragging = false;
  const cleanup = [
    listen(element, 'pointerdown', (event) => { if (event.button !== 0) return; dragging = true; element.setPointerCapture(event.pointerId); }),
    listen(element, 'pointermove', (event) => { if (dragging) { const box = workspace.getBoundingClientRect(); apply((event.clientX - box.left) / box.width * 100); } }),
    listen(element, 'pointerup', () => { dragging = false; }),
    listen(element, 'pointercancel', () => { dragging = false; }),
    listen(element, 'lostpointercapture', () => { dragging = false; }),
    listen(element, 'dblclick', () => apply(initial)),
    listen(element, 'keydown', (event) => {
      const value = { ArrowLeft: percent - 2, ArrowRight: percent + 2, Home: 25, End: 80 }[event.key];
      if (value !== undefined) { event.preventDefault(); apply(value); }
    }),
  ];
  apply(percent, false);
  return () => cleanup.forEach((remove) => remove());
}

// Small inline icons, drawn with the current text color.
const ICONS = {
  screen: 'M2.5 3.5h11v7h-11zM6 13.5h4M8 10.5v3',
  terminal: 'M2.5 3.5h11v9h-11zM5 7l2 1.5L5 10M8.5 10.5h2.5',
  pin: 'M6 2.5h4M7 2.5v4L5 9h6L9 6.5v-4M8 9v4.5',
};
function icon(el, parent, name, label) {
  const svg = el('svg:svg', { viewBox: '0 0 16 16', class: `icon icon-${name}`, ...(label ? { role: 'img', 'aria-label': label } : { 'aria-hidden': 'true' }) }, parent);
  if (label) el('svg:title', { text: label }, svg);
  el('svg:path', { d: ICONS[name], fill: 'none', stroke: 'currentColor', 'stroke-width': '1.4', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, svg);
  return svg;
}

// The kinds of the standard panels. The page server sorts the panels; a
// page's own panels are the other kinds.
const STANDARD = ['packets', 'events', 'map', 'left_the_box', 'containment', 'labels'];

// Mounts one panel by its kind into `content`, and returns its dispose.
function panel(services, page, content, options, controls) {
  const { el } = scoped(content);
  const host = (mount) => mount(content, services, { ...options, controls, status: page.hosts.find((item) => item.name === options.host)?.status });
  try {
    switch (options.kind) {
      case 'screen': return host(screen);
      case 'terminal': return host(terminal);
      case 'packets': return packets(content, services, options);
      case 'labels': return labels(content, services, options);
      case 'containment': return containment(content, services, options);
      case 'left_the_box': return leftTheBox(content, services, options);
      case 'events': return events(content, services, options);
      case 'map': return map(content, services, options);
      case 'table': return table(content, services, options);
      case 'event_table': return eventTable(content, services, options);
      case 'control': return control(content, services, options);
      case 'custom': return custom(content, services, options);
      default: el('p', { class: 'empty-note', text: 'This panel is unavailable. Rebuild the demo.' }, content); return () => {};
    }
  } catch (error) {
    content.replaceChildren(el('p', { class: 'empty-note', text: `Could not open ${options.title}: ${error.message}` }));
    return () => {};
  }
}

// The inspector: one tab per inspector panel, in the server's order, except
// that a page can open on its own panel. Sets `services.showPanel`, and
// returns `show(kind or id)`, `hide` and `reopen` for when the browser tab
// is hidden and shown, and `dispose`.
function inspector(root, services, page) {
  const { $, el } = scoped(root);
  const cleanup = [];
  let stopPanel = () => {}, selected;
  const panels = page.panels.filter((item) => item.area === 'inspector');
  // A page's chosen panel goes first and opens first, and its other own
  // panels follow it in the order the page declared them.
  if (panels.some((item) => item.id === page.inspector_first)) {
    const rank = (item) => (item.id === page.inspector_first ? 0 : STANDARD.includes(item.kind) ? 2 : 1);
    panels.sort((a, b) => rank(a) - rank(b));
  }
  const tabs = [];
  function activate(item) {
    stopPanel();
    selected = item;
    for (const entry of tabs) {
      entry.button.setAttribute('aria-selected', String(entry === item));
      entry.button.tabIndex = entry === item ? 0 : -1;
    }
    const content = $('inspector-content');
    content.replaceChildren();
    content.dataset.kind = item.options.kind;
    content.setAttribute('aria-labelledby', item.button.id);
    stopPanel = panel(services, page, content, item.options);
  }
  const list = $('tabs');
  list.replaceChildren();
  for (const options of panels) {
    const button = el('button', { id: `tab-${options.id}`, type: 'button', role: 'tab', 'aria-controls': 'inspector-content', 'aria-selected': 'false', text: options.title }, list);
    button.tabIndex = -1;
    const item = { button, options };
    tabs.push(item);
    cleanup.push(listen(button, 'click', () => activate(item)));
    cleanup.push(listen(button, 'keydown', (event) => {
      let index = tabs.indexOf(item);
      if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') index = (index + tabs.length - 1) % tabs.length;
      else if (event.key === 'Home') index = 0;
      else if (event.key === 'End') index = tabs.length - 1;
      else if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(item); return; }
      else return;
      event.preventDefault();
      tabs.forEach((entry, i) => { entry.button.tabIndex = i === index ? 0 : -1; });
      tabs[index].button.focus();
    }));
  }
  // A panel kind, or a panel id for the panels that share a kind, such as custom ones.
  const tabOf = (name) => tabs.find((tab) => tab.options.kind === name) || tabs.find((tab) => tab.options.id === name);
  const show = (name) => { const item = tabOf(name); if (item) activate(item); };
  services.showPanel = show;
  if (tabs.length) activate(tabs[0]);
  else $('inspector-content').replaceChildren(el('p', { class: 'empty-note', text: 'This demo declares no inspector panels.' }));
  return {
    show,
    hide() { stopPanel(); stopPanel = () => {}; },
    reopen() { if (selected) activate(selected); },
    dispose() { stopPanel(); cleanup.forEach((remove) => remove()); },
  };
}

// The workspace: the pinned hosts, or the selected one, each in a tile with
// its screen or terminal; or the page's own workspace panel.
function workspace(root, services, page) {
  const { $, el } = scoped(root);
  const document = root.ownerDocument;
  const tiles = new Map(), pinned = new Set(), modes = new Map();
  const custom = page.panels.find((item) => item.area === 'workspace' && item.kind === 'custom');
  const shared = Boolean(custom && page.panels.some((item) => item.area === 'workspace' && ['screen', 'terminal'].includes(item.kind)));
  let stopCustom = () => {}, customMounted = false;
  for (const host of page.hosts) if (host.pinned && !custom) pinned.add(host.name);
  $('workspace').classList.toggle('shared-workspace', shared);
  $('workbench').classList.toggle('shared-workbench', shared);
  const stopDivider = divider($('divider'), $('workbench'), page.title, shared ? 68 : DEFAULT_SPLIT);
  function render(focusHost) {
    if (document.hidden) return;
    const area = $('workspace');
    if (custom && !customMounted) {
      area.replaceChildren();
      const content = el('section', { class: 'custom-workspace' }, area);
      const off = panel(services, page, content, custom);
      customMounted = true;
      stopCustom = () => { off(); content.remove(); customMounted = false; };
    }
    if (custom && !shared) return;
    const names = pinned.size ? [...pinned] : [services.selection.get().host || page.hosts[0]?.name].filter(Boolean);
    // The shared layout gives each console its own row above the inspector.
    $('workbench').style.setProperty('--console-count', String(Math.max(names.length, 1)));
    for (const [name, tile] of tiles) {
      if (!names.includes(name) || tile.mode !== modes.get(name)) { tile.dispose(); tile.root.remove(); tiles.delete(name); }
    }
    if (!names.length && !custom) {
      area.replaceChildren(el('div', { class: 'notice' }, null));
      const card = el('div', { class: 'card' }, area.firstChild);
      el('h2', { text: 'No hosts' }, card);
      el('p', { text: 'This demo declares no hosts. Its panels are in the inspector.' }, card);
      return;
    }
    if (!tiles.size && !custom) area.replaceChildren();
    for (const name of names) {
      const host = page.hosts.find((item) => item.name === name);
      const offered = ['screen', 'terminal'].filter((kind) => host[kind]);
      if (!modes.has(name) || !offered.includes(modes.get(name))) modes.set(name, offered[0] || 'screen');
      if (tiles.has(name)) continue;
      const mode = modes.get(name);
      const tile = el('section', { class: 'workspace-tile', 'aria-label': name }, area);
      if (shared && mode === 'screen') tile.style.alignSelf = 'start';
      const header = el('header', {}, tile);
      el('h2', { text: name }, header);
      const removers = [];
      if (offered.length > 1) {
        const group = el('div', { class: 'segmented', role: 'group', 'aria-label': `${name} console` }, header);
        for (const kind of offered) {
          const button = el('button', { type: 'button', 'aria-pressed': String(kind === mode), text: kind === 'screen' ? 'Screen' : 'Terminal' }, group);
          removers.push(listen(button, 'click', () => { if (modes.get(name) !== kind) { modes.set(name, kind); render(kind === 'terminal' ? name : undefined); } }));
        }
      }
      el('span', { class: 'grow' }, header);
      const controls = el('div', { class: 'tile-controls' }, header);
      const content = el('div', { class: 'tile-console' }, tile);
      let off = () => {};
      if (offered.includes(mode)) {
        const options = page.panels.find((item) => item.kind === mode && item.host === name) || { kind: mode, host: name, title: name };
        off = panel(services, page, content, { ...options, focus: name === focusHost }, controls);
      } else {
        const card = el('div', { class: 'console-card' }, el('div', { class: 'console-stage' }, content));
        el('p', { text: `${name} offers no screen or terminal.` }, card);
      }
      tiles.set(name, { root: tile, mode, dispose() { removers.forEach((remove) => remove()); off(); } });
    }
    area.dataset.tiles = String(names.length);
  }
  function hide() {
    stopCustom(); stopCustom = () => {};
    tiles.forEach((tile) => { tile.dispose(); tile.root.remove(); });
    tiles.clear();
  }
  return {
    render, hide,
    // Pins are hidden when the page's own panel has the workspace to itself.
    pinnable: !custom || shared,
    pinned: (name) => pinned.has(name),
    togglePin(name) { if (pinned.has(name)) pinned.delete(name); else pinned.add(name); render(); },
    dispose() { hide(); stopDivider(); },
  };
}

// The host bar: a chip per host with its readiness, addresses, consoles and
// who holds its input, and a pin that keeps it in the workspace.
function hostBar(root, services, page, area) {
  const { $, el } = scoped(root);
  const cleanup = [];
  const selectHost = (host) => services.selection.set({ host, node: null, links: [], event: null, connection: null, request: null });
  const bar = $('host-bar');
  bar.replaceChildren();
  const all = el('button', { type: 'button', class: 'host-chip all', 'aria-pressed': 'true', text: 'All hosts' }, bar);
  cleanup.push(listen(all, 'click', () => selectHost(null)));
  const chips = new Map();
  for (const host of page.hosts) {
    const group = el('div', { class: 'host-group' }, bar);
    const chip = el('button', { type: 'button', class: 'host-chip', 'aria-pressed': 'false' }, group);
    const dot = el('i', { class: 'readiness', 'data-state': 'booting', 'aria-hidden': 'true' }, chip);
    el('b', { text: host.name }, chip);
    const addresses = el('span', { class: 'host-addresses' }, chip);
    const ready = el('span', { class: 'pill', text: 'Booting' }, chip);
    const marks = el('span', { class: 'console-marks' }, chip);
    const owner = el('span', { class: 'host-owner' }, chip);
    const label = () => `${area.pinned(host.name) ? 'Unpin' : 'Pin'} ${host.name} ${area.pinned(host.name) ? 'from' : 'to'} the workspace`;
    const pin = el('button', { type: 'button', class: 'pin', 'aria-label': label(), title: 'Pin to the workspace', 'aria-pressed': String(area.pinned(host.name)) }, group);
    icon(el, pin, 'pin');
    pin.hidden = !area.pinnable;
    chips.set(host.name, chip);
    cleanup.push(listen(chip, 'click', () => selectHost(host.name)));
    cleanup.push(listen(pin, 'click', () => {
      area.togglePin(host.name);
      pin.setAttribute('aria-pressed', String(area.pinned(host.name)));
      pin.setAttribute('aria-label', label());
    }));
    cleanup.push(services.state(host.status, ({ value }) => {
      const state = value?.state || 'booting';
      ready.textContent = READINESS[state] || 'Booting';
      dot.dataset.state = state;
      addresses.textContent = (value?.addresses || []).join(' · ');
      marks.replaceChildren();
      if (host.screen) icon(el, marks, 'screen', value?.screen ? 'Screen available' : 'No screen yet').classList.toggle('off', !value?.screen);
      if (host.terminal) icon(el, marks, 'terminal', value?.terminal ? 'Terminal available' : 'No terminal yet').classList.toggle('off', !value?.terminal);
    }, (error) => { ready.textContent = `Status unavailable: ${error.message}`; }));
    // Every viewer sees who holds each host's input, whether or not it
    // shows the screen.
    cleanup.push(services.input.subscribe(host.name, ({ owner: who, text }) => {
      owner.textContent = text;
      owner.dataset.owner = who;
    }));
  }
  cleanup.push(services.selection.subscribe(({ host }) => {
    all.setAttribute('aria-pressed', String(!host));
    for (const [name, chip] of chips) chip.setAttribute('aria-pressed', String(name === host));
  }));
  return () => cleanup.forEach((remove) => remove());
}

// The run status and clock, from the graph's watch. A tab opened late shows
// the run time as soon as the snapshot comes, not at the next tick.
function runClock(root, services) {
  const { $ } = scoped(root);
  const clock = services.clock;
  const tick = () => { $('run-clock').textContent = format.fmtDuration(services.runTime()); };
  const status = (state, text) => { $('run-status').dataset.state = state; $('page-status').textContent = text; services.run.set(state); tick(); };
  const stop = services.graph.subscribe((name, value) => {
    if (name === 'waiting') status('connecting', 'Waiting for the world');
    if (name === 'snapshot') { Object.assign(clock, { t: value.t, at: performance.now(), ended: value.ended }); status(value.ended ? 'stopped' : 'running', value.ended ? 'Stopped' : 'Running'); }
    if (name === 'counters') { clock.t = value.t; clock.at = performance.now(); }
    if (name === 'ended') { Object.assign(clock, { t: value.t, at: performance.now(), ended: true }); status('stopped', 'Stopped'); }
    if (name === 'end') { clock.t = services.runTime(); clock.ended = true; status('stopped', 'Stopped'); }
    if (name === 'error' && !clock.ended) status('connecting', 'Reconnecting');
    if (name === 'open' && $('run-status').dataset.state === 'connecting' && !clock.ended) status('running', 'Running');
    if (name === 'world_error') status('stopped', value.error);
  });
  tick();
  const timer = setInterval(tick, 1000);
  return () => { clearInterval(timer); stop(); };
}

// Story moments: the newest one the world marked is the banner.
function moments(root, services, page, panels, signal) {
  const { $ } = scoped(root);
  const document = root.ownerDocument;
  const seen = new Set(), cursors = new Map();
  let latest = -1, bannerEvent, timer, stopped = false;
  const stopBanner = listen($('moment-banner'), 'click', () => {
    if (!bannerEvent) return;
    services.selection.set({ host: services.hostOf(bannerEvent.sandbox?.name), event: bannerEvent, node: bannerEvent.node || null, connection: bannerEvent.conn ?? null, request: bannerEvent.fields?.request_id ?? null, links: [] });
    panels.show('events');
  });
  async function read() {
    for (const moment of page.moments || []) {
      if (stopped) return;
      try {
        const reply = await services.transport.get(moment.events, { after: cursors.get(moment.id) || 0 }, signal);
        if (stopped) return;
        $('moment-status').textContent = '';
        cursors.set(moment.id, reply.next);
        for (const event of reply.rows) services.markMoment(event);
        const event = reply.rows[0];
        if (!event || seen.has(moment.id)) continue;
        seen.add(moment.id);
        if (event.at >= latest) {
          latest = event.at;
          bannerEvent = event;
          $('moment-title').textContent = moment.title;
          $('moment-time').textContent = `at ${format.fmtDuration(event.at)}`;
          $('moment-banner').hidden = false;
        }
      } catch (error) {
        // A stopped run's page server is gone; the moments already shown stay.
        if (services.stopped()) return;
        if (!stopped) $('moment-status').textContent = `Could not read moments: ${error.message}`;
      }
    }
    if (!stopped && page.moments?.length) timer = setTimeout(read, document.hidden ? 5000 : 1000);
  }
  void read();
  return () => { stopped = true; clearTimeout(timer); stopBanner(); };
}

// The app: a header with the demo's name, its World menu and whether the
// run is live; the agent's Screen and Terminal on the left; and the page's
// own world panel on the right. The world panel puts its controls in
// `services.worldMenu`. Returns dispose.
export function appShell(root, services, page) {
  const { el } = scoped(root);
  const document = root.ownerDocument;
  root.replaceChildren();
  root.classList.add('demo-app');
  const header = el('header', { class: 'app-top' }, root);
  const brand = el('div', { class: 'app-brand' }, header);
  el('span', { class: 'app-mark', 'aria-hidden': 'true' }, brand);
  el('span', { text: 'Fictionet' }, brand);
  el('span', { class: 'app-sep', 'aria-hidden': 'true' }, brand);
  el('b', { text: page.title }, brand);
  const right = el('div', { class: 'app-right' }, header);
  const menu = el('div', { class: 'app-menu' }, right);
  const toggle = el('button', { type: 'button', class: 'app-menu-button', 'aria-expanded': 'false', 'aria-controls': 'world-menu', text: 'World' }, menu);
  el('i', { 'aria-hidden': 'true', text: '▾' }, toggle);
  const pop = el('div', { id: 'world-menu', class: 'app-pop', role: 'group', 'aria-label': 'World' }, menu);
  pop.hidden = true;
  services.worldMenu = el('div', { class: 'app-world-controls' }, pop);
  const packetRow = el('div', { class: 'row app-packet-filter' }, pop);
  el('span', { text: 'Packets' }, packetRow);
  const packetSegment = el('div', { class: 'seg', role: 'group', 'aria-label': 'Packets' }, packetRow);
  const packetCleanup = [];
  for (const [value, text] of [['conversations', 'Conversations'], ['every', 'Every packet']]) {
    const button = el('button', { type: 'button', text, 'aria-pressed': 'false' }, packetSegment);
    packetCleanup.push(listen(button, 'click', () => services.packetFilter.set(value)));
    packetCleanup.push(services.packetFilter.subscribe((choice) => button.setAttribute('aria-pressed', String(choice === value))));
  }
  const live = el('span', { class: 'app-live', role: 'status', 'data-live': 'false', text: 'Booting' }, right);
  const body = el('main', { class: 'app-body' }, root);
  const agent = el('section', { class: 'app-agent', 'aria-label': 'Agent' }, body);
  const bar = el('div', { class: 'app-tabs', role: 'tablist', 'aria-label': 'Agent' }, agent);
  const controls = el('div', { class: 'app-controls' });
  const stage = el('div', { id: 'app-agent-panel', class: 'app-stage', role: 'tabpanel' }, agent);
  const world = el('section', { class: 'app-world', 'aria-label': 'World' }, body);
  const own = page.panels.find((item) => item.area === 'workspace' && item.kind === 'custom');
  const worldTabs = el('div', { class: 'app-tabs', role: 'tablist', 'aria-label': 'World' }, world);
  const ownTab = own ? el('button', { id: 'app-world-tab', type: 'button', role: 'tab', 'aria-selected': 'true', 'aria-controls': 'app-world-panel', tabindex: '0', text: own.title }, worldTabs) : null;
  const packetTab = el('button', { id: 'app-packets-tab', type: 'button', role: 'tab', 'aria-selected': String(!own), 'aria-controls': 'app-packets-panel', tabindex: own ? '-1' : '0', text: 'Packets' }, worldTabs);
  const ownPanel = own ? el('div', { id: 'app-world-panel', role: 'tabpanel', 'aria-labelledby': 'app-world-tab', tabindex: '0' }, world) : null;
  const packetPanel = el('div', { id: 'app-packets-panel', role: 'tabpanel', 'aria-labelledby': 'app-packets-tab', tabindex: '0' }, world);
  packetPanel.hidden = Boolean(own);
  packetPanel.inert = Boolean(own);
  let stopPackets = null, packetVisible = !own, disposed = false;
  const packetVisibility = store(false);
  function watchPackets() {
    if (!disposed && !document.hidden && packetVisible && !stopPackets) {
      stopPackets = packets(packetPanel, services, { compact: true, maxRows: 40, visibility: packetVisibility });
    }
    packetVisibility.set(!disposed && !document.hidden && packetVisible);
  }
  function selectWorld(showPackets, focus = false) {
    const changed = packetVisible !== showPackets;
    packetVisible = showPackets;
    packetPanel.hidden = !showPackets;
    packetPanel.inert = !showPackets;
    if (ownPanel) { ownPanel.hidden = showPackets; ownPanel.inert = showPackets; }
    for (const [tab, selected] of [[packetTab, showPackets], [ownTab, !showPackets]]) {
      if (!tab) continue;
      tab.setAttribute('aria-selected', String(selected));
      tab.setAttribute('tabindex', selected ? '0' : '-1');
      if (focus && selected) tab.focus();
    }
    if (changed) watchPackets();
  }
  const host = page.hosts[0];
  const kinds = ['screen', 'terminal'].filter((kind) => host?.[kind]);
  const cleanup = packetCleanup;
  let selected = kinds[0];
  const consoles = new Map();
  function stopConsole() { consoles.forEach((entry) => entry.off()); consoles.clear(); stage.replaceChildren(); controls.replaceChildren(); }
  const tabs = new Map();
  function open(focus = false) {
    for (const [kind, tab] of tabs) { tab.setAttribute('aria-selected', String(kind === selected)); tab.setAttribute('tabindex', kind === selected ? '0' : '-1'); }
    stage.dataset.kind = selected || '';
    if (selected) stage.setAttribute('aria-labelledby', `app-agent-${selected}`);
    if (!selected || document.hidden) return;
    if (!consoles.has(selected)) {
      const content = el('div', { class: 'app-console' }, stage);
      const buttons = el('div', { class: 'app-console-controls' }, controls);
      const options = page.panels.find((item) => item.kind === selected && item.host === host.name) || { kind: selected, host: host.name, title: host.name };
      const off = panel(services, page, content, { ...options, focus, interactive: true }, buttons);
      consoles.set(selected, { content, buttons, off });
    }
    for (const [kind, entry] of consoles) {
      entry.content.hidden = kind !== selected;
      entry.content.inert = kind !== selected;
      entry.buttons.hidden = kind !== selected;
    }
  }
  for (const kind of kinds) {
    const tab = el('button', { type: 'button', role: 'tab', id: `app-agent-${kind}`, 'aria-controls': 'app-agent-panel', 'aria-selected': 'false', text: kind === 'screen' ? 'Screen' : 'Terminal' }, bar);
    tabs.set(kind, tab);
    cleanup.push(listen(tab, 'click', () => { if (selected !== kind) { selected = kind; open(kind === 'terminal'); } }));
  }
  cleanup.push(listen(bar, 'keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key) || !kinds.length) return;
    event.preventDefault();
    const step = event.key === 'ArrowLeft' ? -1 : 1;
    selected = event.key === 'Home' ? kinds[0] : event.key === 'End' ? kinds.at(-1) : kinds[(kinds.indexOf(selected) + step + kinds.length) % kinds.length];
    open(selected === 'terminal');
    tabs.get(selected).focus();
  }));
  bar.append(controls);
  open();
  if (ownTab) cleanup.push(listen(ownTab, 'click', () => selectWorld(false)));
  cleanup.push(listen(packetTab, 'click', () => selectWorld(true)));
  cleanup.push(listen(worldTabs, 'keydown', (event) => {
    if (!ownTab || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    selectWorld(event.key === 'End' || (event.key !== 'Home' && !packetVisible), true);
  }));
  watchPackets();
  const close = () => {
    const focused = pop.contains(document.activeElement);
    pop.hidden = true; pop.inert = true; toggle.setAttribute('aria-expanded', 'false');
    if (focused) toggle.focus();
  };
  services.closeWorldMenu = close;
  cleanup.push(() => { delete services.closeWorldMenu; });
  if (own) cleanup.push(panel(services, page, ownPanel, own));
  cleanup.push(listen(toggle, 'click', () => {
    pop.hidden = !pop.hidden;
    pop.inert = pop.hidden;
    toggle.setAttribute('aria-expanded', String(!pop.hidden));
  }));
  cleanup.push(listen(document, 'keydown', (event) => { if (event.key === 'Escape' && !pop.hidden) { close(); toggle.focus(); } }));
  cleanup.push(listen(document, 'pointerdown', (event) => { if (!menu.contains(event.target)) close(); }));
  let desktopUp = false;
  const status = (text, on) => { live.textContent = on && !desktopUp ? 'Booting' : text; live.dataset.live = String(on && desktopUp); };
  if (host) cleanup.push(services.state(host.status || `/api/state/host-${host.name}`, ({ value }) => {
    desktopUp = value?.state === 'desktop_up';
    if (!services.stopped()) status('Live', true);
  }));
  cleanup.push(services.graph.subscribe((name, value) => {
    if (name === 'waiting') status('Waiting for the world', false);
    if (name === 'snapshot') { services.run.set(value.ended ? 'stopped' : 'running'); status(value.ended ? 'Stopped' : 'Live', !value.ended); }
    if (name === 'ended' || name === 'end') { services.run.set('stopped'); status('Stopped', false); }
    if (name === 'error' && !services.stopped()) status('Reconnecting', false);
    if (name === 'open' && !services.stopped()) { services.run.set('running'); status('Live', true); }
    if (name === 'world_error') { services.run.set('stopped'); status(value.error, false); }
  }));
  // A hidden browser tab keeps neither console nor packets open.
  cleanup.push(listen(document, 'visibilitychange', () => {
    if (document.hidden) stopConsole(); else open();
    watchPackets();
  }));
  return () => {
    disposed = true;
    stopConsole();
    stopPackets?.();
    cleanup.reverse().forEach((off) => off());
    root.classList.remove('demo-app');
  };
}

// `importModule`, when given, replaces how the page loads modules (see
// createServices).
export async function mount(root, transport, theme, importModule) {
  const { $ } = scoped(root);
  const document = root.ownerDocument;
  const services = createServices(transport, theme, importModule);
  const controller = new AbortController();
  const cleanup = [];
  let disposed = false;
  const stop = () => {
    if (disposed) return;
    disposed = true;
    controller.abort();
    cleanup.reverse().forEach((remove) => remove());
    services.dispose();
    transport.close();
    theme.dispose();
  };
  cleanup.push(listen(globalThis.window, 'pagehide', stop, { once: true }));
  cleanup.push(listen($('notice-action'), 'click', () => globalThis.location?.reload()));

  let page;
  try {
    page = await transport.get('/api/page', {}, controller.signal);
  } catch (error) {
    if (!disposed && root.dataset.state !== 'notice') {
      if (error.status === 401 || error.status === 403 || /authorization|closed/i.test(error.message)) showNotice(root, 'Not signed in', SIGN_IN);
      else showNotice(root, 'Could not open the demo', `${error.message}.`, true);
    }
    return stop;
  }
  if (disposed) return stop;
  root.dataset.state = 'ready';
  services.hosts = page.hosts;
  services.labelState = page.panels.find((item) => item.kind === 'labels')?.state;
  services.labelCommand = page.panels.find((item) => item.kind === 'labels')?.command;
  services.containmentState = page.panels.find((item) => item.kind === 'containment')?.state;
  document.title = `${page.title} · Fictionet`;
  if (page.app) {
    cleanup.push(appShell(root, services, page));
    return stop;
  }
  $('page-title').textContent = page.title;

  const area = workspace(root, services, page);
  cleanup.push(area.dispose);
  cleanup.push(hostBar(root, services, page, area));
  cleanup.push(listen($('clear-scope'), 'click', () => services.selection.set({ host: null, node: null, links: [], event: null, connection: null, request: null })));
  cleanup.push(services.selection.subscribe(({ host }) => {
    $('scope-text').textContent = host ? `Showing ${host}` : 'Showing all hosts';
    $('clear-scope').hidden = !host;
    area.render();
  }));
  const panels = inspector(root, services, page);
  cleanup.push(panels.dispose);
  // A hidden tab keeps no panel or console open.
  cleanup.push(listen(document, 'visibilitychange', () => {
    if (document.hidden) { panels.hide(); area.hide(); } else { area.render(); panels.reopen(); }
  }));
  cleanup.push(runClock(root, services));
  cleanup.push(moments(root, services, page, panels, controller.signal));
  return stop;
}

// One centered card in place of the hosts and panels: not signed in, or the
// page description could not be read.
export function showNotice(root, title, text, action = false) {
  const { $, el } = scoped(root);
  if (!$('notice')) {
    const notice = el('section', { id: 'notice', class: 'notice', role: 'status' }, root);
    notice.style.gridRow = '2';
    const card = el('div', { class: 'card' }, notice);
    el('h2', { id: 'notice-title' }, card);
    el('p', { id: 'notice-text' }, card);
    const reload = el('button', { id: 'notice-action', class: 'button', type: 'button', text: 'Reload' }, card);
    reload.addEventListener('click', () => globalThis.location?.reload());
    root.querySelector('.app-body').hidden = true;
  }
  root.dataset.state = 'notice';
  $('notice').hidden = false;
  $('notice-title').textContent = title;
  $('notice-text').textContent = text;
  $('notice-action').hidden = !action;
  $('host-bar')?.replaceChildren();
  const status = $('run-status') || root.querySelector('.app-live');
  if (status) status.hidden = true;
}

if (typeof document !== 'undefined' && document.querySelector?.('#demo')) {
  const root = document.querySelector('#demo');
  const transport = createTransport({
    setStatus: (kind) => { if (kind === 'ended') showNotice(root, 'Not signed in', SIGN_IN); },
  });
  void mount(root, transport, createTheme(root.querySelector('#theme')));
}
