// The Office panel: the scripted story, then the scanner and the office
// subnet. A cell lights as the world's port map shows a probe to its
// address; a card rises for each machine once its address answers.
import { element, stylesheet, addresses, summary, hosts, count, limits, server, PORTS } from './model.mjs';

const STEP = { waiting: 'Waiting', running: 'Running', done: 'Done', failed: 'Failed' };
const CELL = {
  host: 'a host answered',
  empty: 'no host (unreachable)',
  waiting: 'probed, no answer yet',
  idle: 'not probed yet',
};
const COMMAND = { waiting: 'Next', running: 'Running', done: 'Last', failed: 'Failed' };

export function mount(root, services, options) {
  const document = root.ownerDocument;
  const el = (tag, className, text, parent) => element(document, tag, className, text, parent);
  const cleanups = [];
  const on = (node, name, handler) => {
    node.addEventListener(name, handler);
    cleanups.push(() => node.removeEventListener(name, handler));
  };
  const reduced = () => Boolean(globalThis.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
  stylesheet(document, root);
  const panel = el('div', 'scan-panel office-panel', undefined, root);

  // The story strip.
  const strip = el('section', 'scan-story', undefined, panel);
  strip.setAttribute('aria-label', 'Scripted agent');
  const head = el('div', 'scan-story-head', undefined, strip);
  el('h2', 'scan-eyebrow', 'Scripted agent', head);
  const about = el('span', 'scan-muted', undefined, head);
  const steps = el('ol', 'scan-steps', undefined, strip);
  const command = el('p', 'scan-command', undefined, strip);
  const commandLabel = el('span', 'scan-command-label', '', command);
  const commandText = el('code', '', '', command);
  const storyNote = el('p', 'loss-note', '', strip);
  storyNote.setAttribute('role', 'status');

  // The counts and any limits.
  const totals = el('p', 'office-summary', undefined, panel);
  const figure = (label) => {
    const item = el('span', 'office-figure', undefined, totals);
    const value = el('b', '', '0', item);
    const name = el('span', '', ` ${label}`, item);
    return { value, name };
  };
  const probed = figure('addresses probed');
  const answering = figure('hosts answering');
  const open = figure('open ports');
  const notes = el('p', 'loss-note', '', panel);
  notes.setAttribute('role', 'status');

  // The scanner and the hosts that answered.
  const map = el('div', 'office-map', undefined, panel);
  const left = el('section', 'office-found', undefined, map);
  left.setAttribute('aria-label', 'Scanner and hosts');
  const found = el('h3', 'office-found-title', 'No host has answered yet', left);
  const scanner = el('div', 'office-card office-scanner', undefined, left);
  const scannerHost = services.hosts?.find((host) => host.sandbox === 'scanner');
  const scannerTitle = el('div', 'office-card-title', undefined, scanner);
  el('b', 'office-name', scannerHost?.name || 'scanner', scannerTitle);
  const scannerAddr = el('span', 'scan-muted', 'waiting for its lease', scannerTitle);
  const scannerKind = el('span', 'scan-muted', undefined, scannerTitle);
  // The labels that change when the story says it is a replay.
  const realBadges = [];
  let replay = false;
  function label() {
    about.textContent = replay
      ? 'A replay without VMs: an in-world client sends the story\'s probes, and nmap\'s reports are recorded from a VM run. No model runs.'
      : 'A script types three nmap steps into the workstation terminal. No model runs.';
    scannerKind.textContent = replay ? 'Scanner · in-world stand-in for the VM' : 'Scanner · real Ubuntu VM with nmap';
    for (const badge of realBadges) badge.textContent = server(replay);
  }
  label();
  const list = el('ol', 'office-hosts', undefined, left);

  // The subnet: 256 cells, 16 to a row.
  const subnet = el('section', 'office-subnet', undefined, map);
  subnet.setAttribute('aria-label', 'Office subnet 10.0.0.0/24');
  el('h3', 'scan-eyebrow', 'Office subnet · 10.0.0.0/24', subnet);
  const grid = el('div', 'office-grid', undefined, subnet);
  grid.setAttribute('role', 'img');
  const cells = [];
  for (let row = 0; row < 16; row++) {
    el('span', 'office-row', `.${row * 16}`, grid).setAttribute('aria-hidden', 'true');
    for (let column = 0; column < 16; column++) {
      const last = row * 16 + column;
      const cell = el('span', 'office-cell', undefined, grid);
      cell.dataset.state = 'idle';
      cell.setAttribute('title', `10.0.0.${last}: ${CELL.idle}`);
      cells.push(cell);
    }
  }
  const legend = el('ul', 'scan-legend', undefined, subnet);
  legend.setAttribute('aria-label', 'Cell states');
  for (const state of ['host', 'empty', 'waiting', 'idle']) {
    const item = el('li', '', undefined, legend);
    el('span', 'office-cell', undefined, item).dataset.state = state;
    el('span', '', CELL[state], item);
  }

  // Cards by address, in the order they appeared.
  const cards = new Map();
  let first = true, total = 0, complete = false;
  function card(machine, cell) {
    const item = el('li', 'office-card office-host', undefined, list);
    item.dataset.addr = machine.addr;
    const title = el('div', 'office-card-title', undefined, item);
    el('b', 'office-name', machine.name, title);
    el('span', 'office-addr', machine.addr, title);
    if (machine.kind === 'real') {
      realBadges.push(el('span', 'scan-badge', server(replay), title));
      const host = services.hosts?.find((entry) => entry.sandbox === machine.name);
      if (host) {
        const show = el('button', 'text-button', `Show ${host.name} in the workspace`, item);
        show.setAttribute('type', 'button');
        on(show, 'click', () => services.selection?.set({ host: host.name, node: null, links: [], event: null, connection: null, request: null }));
      }
    } else if (machine.kind === 'simulated') {
      el('span', 'scan-muted', 'Simulated by the world', title);
    } else {
      el('span', 'scan-muted', 'Not one of the world\'s office machines', title);
    }
    if (!first && !reduced() && item.animate && cell.getBoundingClientRect) {
      const from = cell.getBoundingClientRect(), to = item.getBoundingClientRect();
      item.animate([
        { transform: `translate(${from.left - to.left}px, ${from.top - to.top}px) scale(0.25)`, opacity: 0 },
        { transform: 'none', opacity: 1 },
      ], { duration: 650, easing: 'cubic-bezier(0.2, 0.7, 0.2, 1)' });
    }
    return item;
  }

  function render(snapshot) {
    const map = snapshot.value;
    const states = addresses(map);
    states.forEach((state, last) => {
      if (cells[last].dataset.state === state) return;
      cells[last].dataset.state = state;
      cells[last].setAttribute('title', `10.0.0.${last}: ${CELL[state]}`);
    });
    const figures = summary(map);
    probed.value.textContent = figures.probed.toLocaleString('en-US');
    probed.name.textContent = figures.probed === 1 ? ' address probed' : ' addresses probed';
    answering.value.textContent = String(figures.answering);
    answering.name.textContent = figures.answering === 1 ? ' host answering' : ' hosts answering';
    open.value.textContent = String(figures.open);
    open.name.textContent = figures.open === 1 ? ' open port' : ' open ports';
    grid.setAttribute('aria-label', `${count(figures.probed, 'address', 'addresses')} of 256 probed, ${count(figures.answering, 'host')} answering`);
    notes.textContent = limits(snapshot).join(' ');
    const machines = hosts(map);
    let added;
    for (const machine of machines) {
      if (cards.has(machine.addr)) continue;
      const item = card(machine, cells[Number(machine.addr.split('.')[3])]);
      cards.set(machine.addr, item);
      added = item;
    }
    total = (map?.machines || []).length;
    const named = machines.filter((machine) => machine.kind !== 'unnamed').length;
    if (!complete && total && named === total) {
      complete = true;
      found.textContent = `All ${total === 5 ? 'five' : total} hosts answered`;
      services.moment?.(found);
      // Seen live, the card that completed the set carries the moment too.
      if (added && !first) services.moment?.(added);
    } else if (!complete) {
      found.textContent = machines.length ? `${count(machines.length, 'host')} answered` : 'No host has answered yet';
    }
    first = false;
  }

  function renderStory(snapshot) {
    const story = snapshot.value;
    if (Boolean(story?.replay) !== replay) {
      replay = Boolean(story?.replay);
      label();
    }
    steps.replaceChildren();
    for (const [index, step] of (story?.steps || []).entries()) {
      const item = el('li', 'scan-step', undefined, steps);
      item.dataset.state = step.state;
      el('span', 'scan-step-mark', String(index + 1), item);
      const text = el('span', 'scan-step-text', undefined, item);
      el('b', '', step.title, text);
      const exit = step.exit === null || step.exit === undefined
        ? (replay && step.state === 'done' ? ' · recorded report' : '')
        : ` · exit ${step.exit}`;
      el('span', 'scan-muted', `${STEP[step.state] || step.state}${exit}`, text);
    }
    const all = story?.steps || [];
    const shown = all.find((step) => step.state === 'running') || all.findLast?.((step) => step.state !== 'waiting') || all[0];
    commandLabel.textContent = shown ? COMMAND[shown.state] || '' : '';
    commandText.textContent = shown ? shown.command : '';
    command.hidden = !shown;
    storyNote.textContent = snapshot.status?.too_large ? 'The story passed its size limit. The last complete story is shown.' : '';
  }

  const stopStory = services.state(options.state, renderStory, (error) => { storyNote.textContent = `Could not load the story: ${error.message}`; });
  const stopMap = services.state(PORTS, render, (error) => { notes.textContent = `Could not load the port map: ${error.message}`; });
  const stopLease = scannerHost?.status
    ? services.state(scannerHost.status, ({ value }) => {
      const leased = Boolean(value?.addresses?.length);
      scannerAddr.textContent = leased ? value.addresses.join(' · ') : 'waiting for its lease';
      scannerAddr.setAttribute('class', leased ? 'office-addr' : 'scan-muted');
    }, () => { scannerAddr.textContent = 'address unavailable'; })
    : () => {};
  return () => {
    stopStory();
    stopMap();
    stopLease();
    cleanups.forEach((cleanup) => cleanup());
    root.replaceChildren();
  };
}
