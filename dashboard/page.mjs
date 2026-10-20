// The demo page: a host bar, a workspace of consoles beside a tabbed
// inspector, built from the page description the server gives at /api/page.
// Components share one watch stream and one state stream (see streams.mjs).
import { createTransport } from './transport.mjs';
import { createSelection } from './selection.mjs';
import { createTheme } from './theme.mjs';
import { createStateHub, createWatchHub } from './streams.mjs';
import { watchState } from './state.mjs';
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

const SIGNED_OUT = 'Open the URL the demo printed in its terminal.';

// A value components can read and follow.
function store(value) {
  const listeners = new Set();
  return {
    get: () => value,
    set(next) { value = next; listeners.forEach((listener) => listener(value)); },
    subscribe(listener) { listeners.add(listener); listener(value); return () => listeners.delete(listener); },
  };
}

export function createServices(transport, theme) {
  const states = createStateHub(transport);
  const watches = createWatchHub(transport);
  const selection = createSelection();
  const moments = new Set();
  const momentListeners = new Set();
  const clock = { t: 0, at: performance.now(), ended: true };
  return {
    transport, selection, theme, format, dom, clock,
    packetPair: store(null),
    watch: () => watches.subscribe(),
    connect: (graph) => watchState(watches.subscribe(), graph),
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
    dispose() { states.dispose(); watches.dispose(); momentListeners.clear(); },
  };
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

const READINESS = { booting: 'Booting', network_up: 'Network up', ssh_up: 'SSH up', desktop_up: 'Desktop up', stopped: 'Stopped' };
const ORDER = ['packets', 'events', 'map', 'left_the_box', 'containment', 'labels'];

export async function mount(root, transport, theme) {
  const { $, el } = scoped(root);
  const document = root.ownerDocument;
  const cleanup = [];
  const services = createServices(transport, theme);
  const controller = new AbortController();
  const tiles = new Map(), chips = new Map(), pinned = new Set(), modes = new Map();
  let stopPanel = () => {}, stopWorkspace = () => {}, selectedTab, disposed = false, workspaceMounted = false;
  let clockTimer, momentTimer, watch, page;
  const stop = () => {
    if (disposed) return;
    disposed = true;
    controller.abort();
    clearInterval(clockTimer);
    clearTimeout(momentTimer);
    watch?.close();
    stopPanel();
    stopWorkspace();
    tiles.forEach((tile) => tile.dispose());
    cleanup.forEach((remove) => remove());
    services.dispose();
    transport.close();
    theme.dispose();
  };
  cleanup.push(listen(globalThis.window, 'pagehide', stop, { once: true }));

  const notice = (title, text, action) => showNotice(root, title, text, action);
  cleanup.push(listen($('notice-action'), 'click', () => globalThis.location?.reload()));

  try {
    page = await transport.get('/api/page', {}, controller.signal);
  } catch (error) {
    if (!disposed && root.dataset.state !== 'notice') {
      if (error.status === 401 || error.status === 403 || /authorization|closed/i.test(error.message)) notice('Not signed in', SIGNED_OUT);
      else notice('Could not open the demo', `${error.message}.`, true);
    }
    return stop;
  }
  if (disposed) return stop;
  root.dataset.state = 'ready';
  services.hosts = page.hosts;
  document.title = `${page.title} · Fictionet`;
  $('page-title').textContent = page.title;

  // The host bar.
  const selectHost = (host) => services.selection.set({ host, node: null, links: [], event: null, connection: null, request: null });
  const bar = $('host-bar');
  bar.replaceChildren();
  const all = el('button', { type: 'button', class: 'host-chip all', 'aria-pressed': 'true', text: 'All hosts' }, bar);
  cleanup.push(listen(all, 'click', () => selectHost(null)));
  const customWorkspace = page.panels.find((panel) => panel.area === 'workspace' && panel.kind === 'custom');
  const sharedWorkspace = customWorkspace && page.panels.some((panel) => panel.area === 'workspace' && ['screen', 'terminal'].includes(panel.kind));
  $('workspace').classList.toggle('shared-workspace', Boolean(sharedWorkspace));
  $('workbench').classList.toggle('shared-workbench', Boolean(sharedWorkspace));
  cleanup.push(divider($('divider'), $('workbench'), page.title, sharedWorkspace ? 68 : DEFAULT_SPLIT));
  for (const host of page.hosts) {
    if (host.pinned && !customWorkspace) pinned.add(host.name);
    const group = el('div', { class: 'host-group' }, bar);
    const chip = el('button', { type: 'button', class: 'host-chip', 'aria-pressed': 'false' }, group);
    const dot = el('i', { class: 'readiness', 'data-state': 'booting', 'aria-hidden': 'true' }, chip);
    el('b', { text: host.name }, chip);
    const addresses = el('span', { class: 'host-addresses' }, chip);
    const ready = el('span', { class: 'pill', text: 'Booting' }, chip);
    const marks = el('span', { class: 'console-marks' }, chip);
    const owner = el('span', { class: 'host-owner' }, chip);
    const pin = el('button', { type: 'button', class: 'pin', 'aria-label': `${pinned.has(host.name) ? 'Unpin' : 'Pin'} ${host.name} ${pinned.has(host.name) ? 'from' : 'to'} the workspace`, title: 'Pin to the workspace', 'aria-pressed': String(pinned.has(host.name)) }, group);
    icon(el, pin, 'pin');
    pin.hidden = Boolean(customWorkspace && !sharedWorkspace);
    chips.set(host.name, { chip, pin, owner });
    cleanup.push(listen(chip, 'click', () => selectHost(host.name)));
    cleanup.push(listen(pin, 'click', () => {
      if (pinned.has(host.name)) pinned.delete(host.name); else pinned.add(host.name);
      pin.setAttribute('aria-pressed', String(pinned.has(host.name)));
      pin.setAttribute('aria-label', `${pinned.has(host.name) ? 'Unpin' : 'Pin'} ${host.name} ${pinned.has(host.name) ? 'from' : 'to'} the workspace`);
      renderWorkspace();
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
  }
  const ownership = (name, text) => {
    const entry = chips.get(name);
    if (!entry) return;
    entry.owner.textContent = text === 'Watching' ? '' : text;
    entry.owner.dataset.owner = text === 'You have control' ? 'mine' : text === 'Watching' ? 'none' : 'other';
  };
  // Every viewer sees who holds each host's input, whether or not it shows
  // the screen. `sessions` holds this tab's connected screen per host.
  const sessions = new Map();
  let leases = {};
  const owners = () => {
    for (const name of chips.keys()) {
      const holder = leases?.[name]?.holder;
      ownership(name, !holder ? 'Watching' : holder === sessions.get(name) ? 'You have control' : 'Another viewer has control');
    }
  };
  cleanup.push(services.state('/api/state/leases', ({ value }) => { leases = value || {}; owners(); }, () => {
    for (const name of chips.keys()) ownership(name, 'Input status unavailable');
  }));

  // The inspector.
  services.labelState = page.panels.find((panel) => panel.kind === 'labels')?.state;
  services.containmentState = page.panels.find((panel) => panel.kind === 'containment')?.state;
  services.labelCommand = page.panels.find((panel) => panel.kind === 'labels')?.command;
  const panels = page.panels.filter((panel) => panel.area === 'inspector');
  panels.sort((a, b) => (ORDER.indexOf(a.kind) < 0 ? ORDER.length : ORDER.indexOf(a.kind)) - (ORDER.indexOf(b.kind) < 0 ? ORDER.length : ORDER.indexOf(b.kind)));
  // A page can open on its own panel: it goes first and opens first.
  const first = panels.findIndex((panel) => panel.id === page.inspector_first);
  if (first > 0) panels.unshift(...panels.splice(first, 1));
  const tabs = [];
  const consoleOptions = (options, controls) => ({
    ...options, controls,
    status: page.hosts.find((host) => host.name === options.host)?.status,
    onSession: (session) => {
      if (session) sessions.set(options.host, session); else sessions.delete(options.host);
      owners();
    },
  });
  function panel(content, options, controls) {
    try {
      switch (options.kind) {
        case 'screen': return screen(content, services, consoleOptions(options, controls));
        case 'terminal': return terminal(content, services, consoleOptions(options, controls));
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
  function activate(item, focus = false) {
    stopPanel();
    selectedTab = item;
    for (const entry of tabs) {
      entry.button.setAttribute('aria-selected', String(entry === item));
      entry.button.tabIndex = entry === item ? 0 : -1;
    }
    item.button.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
    if (focus) item.button.focus();
    const content = $('inspector-content');
    content.replaceChildren();
    content.dataset.kind = item.options.kind;
    content.setAttribute('aria-labelledby', item.button.id);
    stopPanel = panel(content, item.options);
  }
  const tabList = $('tabs');
  tabList.replaceChildren();
  for (const options of panels) {
    const button = el('button', { id: `tab-${options.id}`, type: 'button', role: 'tab', 'aria-controls': 'inspector-content', 'aria-selected': 'false', text: options.title }, tabList);
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
      tabs[index].button.scrollIntoView?.({ block: 'nearest', inline: 'nearest' });
    }));
  }
  // The tab strip fades at an edge that has more tabs past it.
  const strip = tabList.parentElement;
  const edges = () => {
    strip.dataset.left = String(tabList.scrollLeft > 1);
    strip.dataset.right = String(tabList.scrollLeft + tabList.clientWidth < tabList.scrollWidth - 1);
  };
  cleanup.push(listen(tabList, 'scroll', edges));
  if (globalThis.ResizeObserver) {
    const observer = new ResizeObserver(edges);
    observer.observe(tabList);
    cleanup.push(() => observer.disconnect());
  }
  const tabOf = (kind) => tabs.find((tab) => tab.options.kind === kind);
  services.showPanel = (kind) => { const item = tabOf(kind); if (item) activate(item); };
  services.openPackets = (id) => {
    services.selection.set({ links: [id] });
    const item = tabOf('packets'); if (item) activate(item);
  };
  services.openLinks = (_from, _to, members) => {
    services.selection.set({ links: members.map(({ e }) => e.id) });
    const item = tabOf('packets'); if (item) activate(item);
  };
  services.showPackets = (pair) => {
    services.packetPair.set(pair);
    const item = tabOf('packets'); if (item) activate(item);
  };

  // The workspace: the pinned hosts, or the selected one, each in a tile.
  function renderWorkspace(focusHost) {
    if (!page || document.hidden) return;
    const workspace = $('workspace');
    if (customWorkspace && !workspaceMounted) {
      workspace.replaceChildren();
      const content = el('section', { class: 'custom-workspace' }, workspace);
      const off = panel(content, customWorkspace);
      workspaceMounted = true;
      stopWorkspace = () => { off(); content.remove(); workspaceMounted = false; };
    }
    if (customWorkspace && !sharedWorkspace) return;
    const names = pinned.size ? [...pinned] : [services.selection.get().host || page.hosts[0]?.name].filter(Boolean);
    workspace.style.setProperty('--console-count', String(Math.max(names.length, 1)));
    for (const [name, tile] of tiles) {
      if (!names.includes(name) || tile.mode !== modes.get(name)) { tile.dispose(); tile.root.remove(); tiles.delete(name); }
    }
    if (!names.length && !customWorkspace) {
      workspace.replaceChildren(el('div', { class: 'notice' }, null));
      const card = el('div', { class: 'card' }, workspace.firstChild);
      el('h2', { text: 'No hosts' }, card);
      el('p', { text: 'This demo declares no hosts. Its panels are in the inspector.' }, card);
      return;
    }
    if (!tiles.size && !customWorkspace) workspace.replaceChildren();
    for (const name of names) {
      const host = page.hosts.find((item) => item.name === name);
      const offered = ['screen', 'terminal'].filter((kind) => host[kind]);
      if (!modes.has(name) || !offered.includes(modes.get(name))) modes.set(name, offered[0] || 'screen');
      if (tiles.has(name)) continue;
      const mode = modes.get(name);
      const tile = el('section', { class: 'workspace-tile', 'aria-label': name }, workspace);
      if (sharedWorkspace && mode === 'screen') tile.style.alignSelf = 'start';
      const header = el('header', {}, tile);
      el('h2', { text: name }, header);
      const removers = [];
      if (offered.length > 1) {
        const group = el('div', { class: 'segmented', role: 'group', 'aria-label': `${name} console` }, header);
        for (const kind of offered) {
          const button = el('button', { type: 'button', 'aria-pressed': String(kind === mode), text: kind === 'screen' ? 'Screen' : 'Terminal' }, group);
          removers.push(listen(button, 'click', () => { if (modes.get(name) !== kind) { modes.set(name, kind); renderWorkspace(kind === 'terminal' ? name : undefined); } }));
        }
      }
      el('span', { class: 'grow' }, header);
      const controls = el('div', { class: 'tile-controls' }, header);
      const content = el('div', { class: 'tile-console' }, tile);
      let off = () => {};
      if (offered.includes(mode)) {
        const options = page.panels.find((item) => item.kind === mode && item.host === name) || { kind: mode, host: name, title: name };
        off = panel(content, { ...options, focus: name === focusHost }, controls);
      } else {
        const card = el('div', { class: 'console-card' }, el('div', { class: 'console-stage' }, content));
        el('p', { text: `${name} offers no screen or terminal.` }, card);
      }
      tiles.set(name, { root: tile, mode, dispose() { removers.forEach((remove) => remove()); off(); } });
    }
    workspace.dataset.tiles = String(names.length);
  }

  cleanup.push(listen($('clear-scope'), 'click', () => selectHost(null)));
  cleanup.push(services.selection.subscribe(({ host }) => {
    all.setAttribute('aria-pressed', String(!host));
    for (const [name, { chip }] of chips) chip.setAttribute('aria-pressed', String(name === host));
    $('scope-text').textContent = host ? `Showing ${host}` : 'Showing all hosts';
    $('clear-scope').hidden = !host;
    renderWorkspace();
  }));
  cleanup.push(listen(document, 'visibilitychange', () => {
    if (document.hidden) {
      stopPanel(); stopPanel = () => {};
      stopWorkspace(); stopWorkspace = () => {};
      tiles.forEach((tile) => { tile.dispose(); tile.root.remove(); });
      tiles.clear();
    } else {
      renderWorkspace();
      if (selectedTab) activate(selectedTab);
    }
  }));
  if (tabs.length) activate(tabs[0]);
  else $('inspector-content').replaceChildren(el('p', { class: 'empty-note', text: 'This demo declares no inspector panels.' }));

  // The run status and clock, from the shared watch. A tab opened late shows
  // the run time as soon as the snapshot comes, not at the next tick.
  const clock = services.clock;
  const tick = () => { $('run-clock').textContent = format.fmtDuration(services.runTime()); };
  const status = (state, text) => { $('run-status').dataset.state = state; $('page-status').textContent = text; tick(); };
  watch = services.watch();
  const on = (name, callback) => cleanup.push(listen(watch, name, (event) => callback(event.data ? JSON.parse(event.data) : null)));
  on('waiting', () => status('connecting', 'Waiting for the world'));
  on('snapshot', (value) => { Object.assign(clock, { t: value.t, at: performance.now(), ended: value.ended }); status(value.ended ? 'stopped' : 'running', value.ended ? 'Stopped' : 'Running'); });
  on('counters', (value) => { clock.t = value.t; clock.at = performance.now(); });
  on('ended', (value) => { Object.assign(clock, { t: value.t, at: performance.now(), ended: true }); status('stopped', 'Stopped'); });
  on('end', () => { clock.t = services.runTime(); clock.ended = true; status('stopped', 'Stopped'); });
  on('error', () => { if (!clock.ended) status('connecting', 'Reconnecting'); });
  on('open', () => { if ($('run-status').dataset.state === 'connecting' && !clock.ended) status('running', 'Running'); });
  on('world_error', (value) => status('stopped', value.error));
  tick();
  clockTimer = setInterval(tick, 1000);

  // Story moments: the newest one the world marked is the banner.
  const seen = new Set(), cursors = new Map();
  let latest = -1, bannerEvent;
  cleanup.push(listen($('moment-banner'), 'click', () => {
    if (!bannerEvent) return;
    const host = page.hosts.find((item) => item.sandbox === bannerEvent.sandbox?.name)?.name || null;
    services.selection.set({ host, event: bannerEvent, node: bannerEvent.node || null, connection: bannerEvent.conn ?? null, request: bannerEvent.fields?.request_id ?? null, links: [] });
    const item = tabOf('events'); if (item) activate(item);
  }));
  async function readMoments() {
    for (const moment of page.moments || []) {
      if (disposed) return;
      try {
        const reply = await transport.get(moment.events, { after: cursors.get(moment.id) || 0 }, controller.signal);
        if (disposed) return;
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
        if (!disposed) $('moment-status').textContent = `Could not read moments: ${error.message}`;
      }
    }
    if (!disposed && page.moments?.length) momentTimer = setTimeout(readMoments, document.hidden ? 5000 : 1000);
  }
  void readMoments();
  return stop;
}

// One centered card in place of the hosts and panels: not signed in, or the
// page description could not be read.
function showNotice(root, title, text, action = false) {
  const { $ } = scoped(root);
  root.dataset.state = 'notice';
  $('notice').hidden = false;
  $('notice-title').textContent = title;
  $('notice-text').textContent = text;
  $('notice-action').hidden = !action;
  $('host-bar').replaceChildren();
  $('run-status').hidden = true;
}

if (typeof document !== 'undefined' && document.querySelector?.('#demo')) {
  const root = document.querySelector('#demo');
  const transport = createTransport({
    setStatus: (kind, text) => { if (kind === 'ended' && text?.startsWith('Not signed in')) showNotice(root, 'Not signed in', SIGNED_OUT); },
  }, { signedOutMessage: `Not signed in. ${SIGNED_OUT}` });
  void mount(root, transport, createTheme(root.querySelector('#theme')));
}
