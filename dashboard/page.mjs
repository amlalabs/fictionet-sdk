import { createTransport } from './transport.mjs';
import { createSelection } from './selection.mjs';
import { createTheme } from './theme.mjs';
import * as format from './format.mjs';
import { scoped, listen } from './dom.mjs';
import { mount as screen } from './components/screen.mjs';
import { mount as terminal } from './components/terminal.mjs';
import { mount as packets } from './components/packets.mjs';
import { mount as events } from './components/events.mjs';
import { mount as map } from './components/map.mjs';
import { mount as table } from './components/table.mjs';
import { mount as eventTable } from './components/event-table.mjs';
import { mount as control } from './components/control.mjs';
import { mount as custom } from './components/custom.mjs';

export function createServices(transport, theme) {
  const topics = new Map();
  const selection = createSelection();
  const moments = new Set();
  const momentListeners = new Set();
  return {
    transport, selection, theme, format,
    moment(element) { element.classList.add('moment'); },
    isMoment: (event) => moments.has(event.seq),
    onMoment(callback) { momentListeners.add(callback); return () => momentListeners.delete(callback); },
    markMoment(event) { moments.add(event.seq); if (moments.size > 1000) moments.delete(moments.values().next().value); momentListeners.forEach((callback) => callback()); },
    state(path, onSnapshot, onError = () => {}) {
      if (!/^\/api\/state\/[A-Za-z0-9_-]{1,128}$/.test(path)) throw new Error('Invalid state path');
      let topic = topics.get(path);
      if (!topic) {
        const source = transport.stateStream(path.slice('/api/state/'.length));
        const controller = new AbortController();
        topic = { listeners: new Set(), latest: null, source, controller, refreshing: false, dirty: false };
        const deliver = (snapshot) => {
          if (controller.signal.aborted || snapshot.revision < (topic.latest?.revision || 0)) return;
          topic.latest = snapshot;
          topic.listeners.forEach((listener) => listener.onSnapshot(snapshot));
        };
        const fail = (error) => { if (!controller.signal.aborted) topic.listeners.forEach((listener) => listener.onError(error)); };
        const refresh = async () => {
          topic.dirty = true;
          if (topic.refreshing) return;
          topic.refreshing = true;
          try {
            while (topic.dirty && !controller.signal.aborted) {
              topic.dirty = false;
              deliver(await transport.get(path, {}, controller.signal));
            }
          } catch (error) { fail(error); }
          finally { topic.refreshing = false; }
        };
        const offSnapshot = listen(source, 'snapshot', (event) => deliver(JSON.parse(event.data)));
        const offDelta = listen(source, 'delta', refresh);
        const onError = (event) => fail(new Error(JSON.parse(event.data).error));
        const offError = listen(source, 'error', onError);
        const offRefusal = listen(source, 'world_error', onError);
        topic.stop = () => { controller.abort(); offSnapshot(); offDelta(); offError(); offRefusal(); source.close(); };
        topics.set(path, topic);
      }
      const listener = { onSnapshot, onError };
      topic.listeners.add(listener);
      if (topic.latest) onSnapshot(topic.latest);
      return () => {
        topic.listeners.delete(listener);
        if (!topic.listeners.size) { topic.stop(); topics.delete(path); }
      };
    },
    dispose() { topics.forEach((topic) => topic.stop()); topics.clear(); momentListeners.clear(); },
  };
}

export function divider(element, workspace, title) {
  let percent = 62;
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
    listen(element, 'dblclick', () => apply(62)),
    listen(element, 'keydown', (event) => {
      const value = { ArrowLeft: percent - 2, ArrowRight: percent + 2, Home: 25, End: 80 }[event.key];
      if (value !== undefined) { event.preventDefault(); apply(value); }
    }),
  ];
  apply(percent, false);
  return () => cleanup.forEach((remove) => remove());
}

export async function mount(root, transport, theme) {
  const { $, el } = scoped(root);
  const cleanup = [];
  const services = createServices(transport, theme);
  services.setStatus = (_, text) => { $('page-status').textContent = text; };
  const controller = new AbortController();
  const tiles = new Map(), chips = new Map(), pinned = new Set(), modes = new Map();
  let stopPanel = () => {}, stopWorkspace = () => {}, selectedTab, disposed = false, workspaceMounted = false;
  let clockTimer, momentTimer, watch;
  const stop = () => {
    if (disposed) return;
    disposed = true;
    controller.abort();
    clearInterval(clockTimer); clearTimeout(momentTimer);
    watch?.close();
    stopPanel(); stopWorkspace(); tiles.forEach((tile) => tile.dispose());
    cleanup.forEach((remove) => remove());
    services.dispose(); transport.close(); theme.dispose();
  };
  cleanup.push(listen(window, 'pagehide', stop, { once: true }));
  let page;
  try { page = await transport.get('/api/page', {}, controller.signal); }
  catch (error) {
    if (!$('page-status').textContent.startsWith('Not signed in.')) $('page-status').textContent = `Could not open the demo: ${error.message}. Reload to retry.`;
    $('workspace').textContent = $('page-status').textContent;
    $('inspector-content').textContent = 'Open a demo URL to view its panels.';
    return stop;
  }
  if (disposed) return stop;
  services.hosts = page.hosts;
  document.title = page.title;
  $('page-title').textContent = page.title;
  $('page-status').textContent = 'Waiting for the world';
  cleanup.push(divider($('divider'), $('workbench'), page.title));
  const readiness = { booting: 'Booting', network_up: 'Network up', ssh_up: 'SSH up', desktop_up: 'Desktop up', stopped: 'Stopped' };
  const selectHost = (host) => services.selection.set({ host, node: null, links: [], event: null, connection: null, request: null });
  const all = el('button', { type: 'button', class: 'host-chip', text: 'All hosts', 'aria-pressed': 'true' }, $('host-bar'));
  cleanup.push(listen(all, 'click', () => selectHost(null)));
  for (const host of page.hosts) {
    const group = el('div', { class: 'host-group' }, $('host-bar'));
    const chip = el('button', { type: 'button', class: 'host-chip', 'aria-pressed': 'false' }, group);
    const dot = el('span', { class: 'readiness', 'aria-hidden': 'true' }, chip);
    const ready = el('span', { text: 'Booting' }, chip);
    el('b', { text: host.name }, chip);
    const addresses = el('span', { class: 'mono host-addresses' }, chip);
    const consoles = el('span', { class: 'host-consoles' }, chip);
    const owner = el('span', { class: 'host-owner', text: 'Watching' }, chip);
    const pin = el('button', { type: 'button', class: 'pin', text: 'Pin', 'aria-label': `Pin ${host.name}`, 'aria-pressed': 'false' }, group);
    pin.hidden = page.panels.some((panel) => panel.area === 'workspace' && panel.kind === 'custom');
    chips.set(host.name, { chip, pin, owner });
    cleanup.push(listen(chip, 'click', () => selectHost(host.name)));
    cleanup.push(listen(pin, 'click', () => {
      if (pinned.has(host.name)) pinned.delete(host.name); else pinned.add(host.name);
      pin.setAttribute('aria-pressed', String(pinned.has(host.name)));
      pin.textContent = pinned.has(host.name) ? 'Unpin' : 'Pin';
      renderWorkspace();
    }));
    cleanup.push(services.state(host.status, ({ value }) => {
      ready.textContent = readiness[value?.state] || 'Booting';
      dot.dataset.state = value?.state || 'booting';
      addresses.textContent = (value?.addresses || []).join(' · ');
      consoles.textContent = `${value?.screen ? 'Screen' : 'No screen'} · ${value?.terminal ? 'Terminal' : 'No terminal'}`;
    }, (error) => { ready.textContent = `Status unavailable: ${error.message}`; }));
  }
  cleanup.push(services.state('/api/state/leases', ({ value }) => {
    for (const [name, { owner }] of chips) owner.textContent = value?.[name]?.holder ? 'Another viewer has control' : 'Watching';
  }, () => { for (const { owner } of chips.values()) owner.textContent = 'Input status unavailable'; }));
  const workspacePanel = page.panels.find((panel) => panel.area === 'workspace' && panel.kind === 'custom');
  const panels = page.panels.filter((panel) => panel.area === 'inspector');
  const order = ['packets', 'events', 'map'];
  panels.sort((a, b) => (order.indexOf(a.kind) < 0 ? 3 : order.indexOf(a.kind)) - (order.indexOf(b.kind) < 0 ? 3 : order.indexOf(b.kind)));
  cleanup.push(listen(document, 'visibilitychange', () => {
    if (document.hidden) { stopPanel(); stopPanel = () => {}; stopWorkspace(); stopWorkspace = () => {}; tiles.forEach((tile) => { tile.dispose(); tile.root.remove(); }); tiles.clear(); }
    else { renderWorkspace(); if (selectedTab) activate(selectedTab); }
  }));
  const tabs = [];
  const hostStatus = (options) => ({ ...options, status: page.hosts.find((host) => host.name === options.host)?.status, onOwnership: (text) => { const chip = chips.get(options.host); if (chip) chip.owner.textContent = text; } });
  function panel(root, options) {
    try {
      switch (options.kind) {
        case 'screen': return screen(root, services, hostStatus(options));
        case 'terminal': return terminal(root, services, hostStatus(options));
        case 'packets': return packets(root, services, options);
        case 'events': return events(root, services, options);
        case 'map': return map(root, services, options);
        case 'table': return table(root, services, options);
        case 'event_table': return eventTable(root, services, options);
        case 'control': return control(root, services, options);
        case 'custom': return custom(root, services, options);
        default: el('p', { text: 'This panel is unavailable. Rebuild the demo.' }, root); return () => {};
      }
    } catch (error) { root.replaceChildren(el('p', { text: `Could not open ${options.title}: ${error.message}` })); return () => {}; }
  }
  function activate(item) {
    stopPanel();
    selectedTab = item;
    for (const entry of tabs) { entry.button.setAttribute('aria-selected', String(entry === item)); entry.button.tabIndex = entry === item ? 0 : -1; }
    const content = $('inspector-content');
    content.replaceChildren();
    content.setAttribute('aria-labelledby', item.button.id);
    stopPanel = panel(content, item.options);
  }
  for (const options of panels) {
    const button = el('button', { id: `tab-${options.id}`, type: 'button', role: 'tab', 'aria-controls': 'inspector-content', 'aria-selected': 'false', text: options.title }, $('tabs'));
    button.tabIndex = -1;
    const item = { button, options }; tabs.push(item);
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
  services.openPackets = (id) => {
    services.selection.set({ links: [id] });
    const item = tabs.find((tab) => tab.options.kind === 'packets'); if (item) activate(item);
  };
  services.openLinks = (_from, _to, members) => {
    services.selection.set({ links: members.map(({ e }) => e.id) });
    const item = tabs.find((tab) => tab.options.kind === 'packets'); if (item) activate(item);
  };
  function renderWorkspace() {
    if (!page || document.hidden) return;
    const workspace = $('workspace');
    if (workspacePanel) {
      if (workspaceMounted) return;
      workspace.replaceChildren();
      const content = el('section', { class: 'custom-workspace' }, workspace);
      const off = panel(content, workspacePanel);
      workspaceMounted = true;
      stopWorkspace = () => { off(); workspaceMounted = false; };
      return;
    }
    const names = pinned.size ? [...pinned] : [services.selection.get().host || page.hosts[0]?.name].filter(Boolean);
    for (const [name, tile] of tiles) if (!names.includes(name) || tile.mode !== (modes.get(name) || 'screen')) { tile.dispose(); tile.root.remove(); tiles.delete(name); }
    if (!names.length) { workspace.textContent = 'No hosts declared. Add a host to this demo.'; return; }
    if (!tiles.size) workspace.replaceChildren();
    for (const name of names) {
      if (tiles.has(name)) continue;
      const host = page.hosts.find((host) => host.name === name);
      const tile = el('section', { class: 'workspace-tile', 'aria-label': name }, workspace);
      const header = el('header', {}, tile);
      el('h2', { text: name }, header);
      const toggle = el('button', { type: 'button' }, header);
      const mode = modes.get(name) || 'screen';
      toggle.textContent = mode === 'screen' ? 'Terminal' : 'Screen';
      const content = el('div', { class: 'tile-console' }, tile);
      const change = listen(toggle, 'click', () => { modes.set(name, mode === 'screen' ? 'terminal' : 'screen'); renderWorkspace(); });
      const offered = host[mode];
      const off = offered ? panel(content, { kind: mode, host: name, title: name }) : () => {};
      if (!offered) content.textContent = `${name} does not offer a ${mode}.`;
      tiles.set(name, { root: tile, mode, dispose() { change(); off(); } });
    }
    workspace.dataset.tiles = String(names.length);
  }
  cleanup.push(listen($('clear-scope'), 'click', () => selectHost(null)));
  cleanup.push(services.selection.subscribe(({ host }) => {
    all.setAttribute('aria-pressed', String(!host));
    for (const [name, { chip }] of chips) chip.setAttribute('aria-pressed', String(name === host));
    $('scope-text').textContent = host ? `Host: ${host}` : 'All hosts';
    $('clear-scope').hidden = !host;
    renderWorkspace();
  }));
  if (tabs.length) activate(tabs[0]); else $('inspector-content').textContent = 'No inspector panels declared.';
  let run = { t: 0, at: performance.now(), ended: true };
  watch = transport.watch();
  const on = (name, callback) => cleanup.push(listen(watch, name, (event) => callback(JSON.parse(event.data))));
  on('snapshot', (value) => { run = { t: value.t, at: performance.now(), ended: value.ended }; $('page-status').textContent = value.ended ? 'Stopped' : 'Running'; });
  on('counters', (value) => { run.t = value.t; run.at = performance.now(); });
  on('ended', (value) => { run = { t: value.t, at: performance.now(), ended: true }; $('page-status').textContent = 'Stopped'; });
  on('end', () => { run.t += run.ended ? 0 : (performance.now() - run.at) / 1000; run.ended = true; $('page-status').textContent = 'Stopped'; });
  on('error', () => { $('page-status').textContent = 'Connection lost. Reconnecting.'; });
  on('world_error', ({ error }) => { $('page-status').textContent = error; });
  const clock = () => { $('run-clock').textContent = format.fmtDuration(run.t + (run.ended ? 0 : (performance.now() - run.at) / 1000)); };
  clock(); clockTimer = setInterval(clock, 1000);
  const seen = new Set(), cursors = new Map(); let latest = -1, bannerEvent;
  cleanup.push(listen($('moment-banner'), 'click', () => { if (bannerEvent) services.selection.set({ host: page.hosts.find((host) => host.sandbox === bannerEvent.sandbox?.name)?.name || null, event: bannerEvent, node: bannerEvent.node || null, connection: bannerEvent.conn ?? null, request: bannerEvent.fields?.request_id ?? null, links: [] }); }));
  async function readMoments() {
    for (const moment of page.moments) {
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
          latest = event.at; bannerEvent = event;
          $('moment-banner').textContent = `${moment.title} · ${format.fmtDuration(event.at)}`;
          $('moment-banner').hidden = false;
        }
      } catch (error) { if (!disposed) $('moment-status').textContent = `Could not read moments: ${error.message}`; }
    }
    if (!disposed) momentTimer = setTimeout(readMoments, 1000);
  }
  void readMoments();
  return stop;
}

if (typeof document !== 'undefined') {
  const theme = createTheme(document.querySelector('#theme'));
  const root = document.querySelector('#demo');
  if (root) {
    const status = root.querySelector('#page-status');
    const transport = createTransport({ setStatus: (_, text) => { status.textContent = text; } }, {
      signedOutMessage: 'Not signed in. Open the URL the demo printed. A URL works in one tab; restart the demo for a new one.',
    });
    void mount(root, transport, theme);
  }
}
