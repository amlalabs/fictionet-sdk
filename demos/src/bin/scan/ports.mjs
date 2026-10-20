// The Ports panel: for each host that answered, its 1,024 scanned TCP ports
// as a grid that fills in as the world's tap sees nmap's probes and their
// answers. A second view compares only the ports open on any host.
import { stylesheet, hosts, ports, counts, openPorts, portState, services as nmapNames, limits, server, OFFICE, SERVICES } from './model.mjs';

const LEGEND = [
  ['open', 'open'],
  ['closed', 'closed'],
  ['unreachable', 'unreachable'],
  ['unanswered', 'probed, no answer yet'],
  ['idle', 'not probed'],
];

export function mount(root, services, options) {
  const { el } = services.dom.scoped(root);
  const cleanups = [];
  const { listen } = services.dom;
  const { plural } = services.format;
  stylesheet(el, root);
  const panel = el('div', { class: 'scan-panel ports-panel' }, root);
  const bar = el('div', { class: 'ports-bar' }, panel);
  const views = el('div', { class: 'segmented' }, bar);
  views.setAttribute('role', 'group');
  views.setAttribute('aria-label', 'Ports view');
  const allButton = el('button', { text: 'All 1,024 ports' }, views);
  const openButton = el('button', { text: 'Open on any host' }, views);
  for (const button of [allButton, openButton]) button.setAttribute('type', 'button');
  const legend = el('ul', { class: 'scan-legend' }, bar);
  legend.setAttribute('aria-label', 'Port states');
  for (const [state, label] of LEGEND) {
    const item = el('li', {}, legend);
    el('span', { class: 'port-cell' }, item).dataset.state = state;
    el('span', { text: label }, item);
  }
  const notes = el('p', { class: 'loss-note' }, panel);
  notes.setAttribute('role', 'status');
  const empty = el('p', { class: 'empty-note', text: 'No host has answered yet. Each host gets a row of its 1,024 ports when it answers.' }, panel);
  const heat = el('div', { class: 'ports-heat' }, panel);
  const compare = el('div', { class: 'ports-compare' }, panel);

  let view = 'all', latest = null, names = new Map(), replay = false;
  const rows = new Map();
  // The labels of the office server's rows, which a replay renames.
  const realLabels = [];
  function setView(next) {
    view = next;
    allButton.setAttribute('aria-pressed', String(view === 'all'));
    openButton.setAttribute('aria-pressed', String(view === 'open'));
    heat.hidden = view !== 'all';
    compare.hidden = view !== 'open';
    draw();
  }
  cleanups.push(listen(allButton, 'click', () => setView('all')));
  cleanups.push(listen(openButton, 'click', () => setView('open')));

  // One host's row: its name, counts, open ports and the 1,024-cell grid.
  function hostRow(machine) {
    const row = el('section', { class: 'ports-host' }, null);
    row.setAttribute('aria-label', `${machine.name} ${machine.addr}`);
    const label = el('div', { class: 'ports-label' }, row);
    const title = el('div', { class: 'ports-title' }, label);
    el('b', { text: machine.name }, title);
    el('span', { class: 'office-addr', text: machine.addr }, title);
    const kind = el('span', { class: 'scan-muted', text: machine.kind === 'real' ? server(replay) : machine.kind === 'simulated' ? 'Simulated' : 'Unnamed address' }, label);
    if (machine.kind === 'real') realLabels.push(kind);
    const tally = el('p', { class: 'ports-tally' }, label);
    const figures = {};
    for (const state of ['open', 'closed', 'unanswered', 'unreachable', 'idle']) {
      const item = el('span', { class: `ports-count is-${state}` }, tally);
      figures[state] = { value: el('b', { text: '0' }, item), name: el('span', {}, item), item };
    }
    const openList = el('p', { class: 'ports-open' }, label);
    const grid = el('div', { class: 'ports-grid' }, row);
    grid.setAttribute('role', 'img');
    const cells = [null];
    for (let port = 1; port <= 1024; port++) {
      const cell = el('span', { class: 'port-cell' }, grid);
      cell.dataset.state = 'idle';
      cells.push(cell);
    }
    return { row, grid, cells, figures, openList, machine };
  }

  function updateRow(entry, map) {
    const states = ports(map, entry.machine.addr);
    for (let port = 1; port <= 1024; port++) {
      if (entry.cells[port].dataset.state === states[port]) continue;
      entry.cells[port].dataset.state = states[port];
      entry.cells[port].setAttribute('title', `${port}/tcp ${states[port] === 'idle' ? 'not probed' : states[port]}`);
    }
    const tally = counts(states);
    const words = { open: 'open', closed: 'closed', unanswered: 'no answer', unreachable: 'unreachable', idle: 'not probed' };
    for (const [state, figure] of Object.entries(entry.figures)) {
      figure.value.textContent = tally[state].toLocaleString('en-US');
      figure.name.textContent = ` ${words[state]}`;
      figure.item.hidden = !tally[state] && state !== 'open' && state !== 'closed';
    }
    entry.grid.setAttribute('aria-label', `${entry.machine.addr}: ${plural(tally.open, 'open port')}, ${tally.closed.toLocaleString('en-US')} closed, ${tally.idle.toLocaleString('en-US')} not probed`);
    const open = [];
    for (let port = 1; port <= 1024; port++) if (states[port] === 'open') open.push(port);
    entry.openList.replaceChildren();
    if (!open.length) return;
    const named = open.some((port) => names.has(`${entry.machine.addr}:${port}`));
    el('span', { class: 'scan-muted', text: named ? 'Open · names: nmap says ' : 'Open ' }, entry.openList);
    for (const port of open) {
      const chip = el('span', { class: 'port-chip' }, entry.openList);
      el('b', { text: String(port) }, chip);
      const service = names.get(`${entry.machine.addr}:${port}`);
      if (service) el('span', { class: 'nmap-says', text: service.service }, chip).setAttribute('title', 'nmap says');
    }
  }

  function drawCompare(map) {
    compare.replaceChildren();
    const columns = openPorts(map);
    const machines = hosts(map);
    if (!machines.length) return;
    if (!columns.length) {
      el('p', { class: 'empty-note', text: 'No port is open on any host yet.' }, compare);
      return;
    }
    el('p', { class: 'scan-muted ports-compare-note', text: `The ${plural(columns.length, 'TCP port')} open on any host. Under each open port, the service name nmap says.` }, compare);
    const table = el('table', { class: 'data-table ports-matrix' }, compare);
    const head = el('tr', {}, el('thead', {}, table));
    el('th', { text: 'Host' }, head).setAttribute('scope', 'col');
    for (const port of columns) el('th', { class: 'ports-matrix-port', text: String(port) }, head).setAttribute('scope', 'col');
    const body = el('tbody', {}, table);
    const words = { idle: 'not probed', unanswered: 'no answer yet' };
    for (const machine of machines) {
      const tr = el('tr', {}, body);
      const th = el('th', {}, tr);
      th.setAttribute('scope', 'row');
      el('b', { text: machine.name }, th);
      el('span', { class: 'office-addr', text: machine.addr }, th);
      for (const port of columns) {
        const state = portState(map, machine.addr, port);
        const td = el('td', { class: 'ports-matrix-cell' }, tr);
        td.dataset.state = state;
        const service = state === 'open' && names.get(`${machine.addr}:${port}`);
        td.setAttribute('title', `${port}/tcp ${words[state] || state}${service ? `, nmap says ${service.service}` : ''}`);
        const mark = el('span', { class: 'port-cell' }, td);
        mark.dataset.state = state;
        mark.setAttribute('role', 'img');
        mark.setAttribute('aria-label', words[state] || state);
        if (service) el('span', { class: 'nmap-says', text: service.service }, td);
      }
    }
  }

  function draw() {
    const map = latest?.value;
    const machines = hosts(map);
    empty.hidden = machines.length > 0;
    notes.textContent = limits(latest, plural).join(' ');
    if (view === 'open') {
      drawCompare(map);
      return;
    }
    // Rows go in address order and stay once added, so nothing jumps.
    machines.forEach((machine, index) => {
      let entry = rows.get(machine.addr);
      if (!entry) {
        entry = hostRow(machine);
        rows.set(machine.addr, entry);
        const next = heat.children[index];
        if (next && next !== entry.row) heat.insertBefore?.(entry.row, next) ?? heat.appendChild(entry.row);
        else heat.appendChild(entry.row);
      }
      updateRow(entry, map);
    });
  }

  const stopMap = services.state(options.state, (snapshot) => { latest = snapshot; draw(); }, (error) => { notes.textContent = `Could not load the port map: ${error.message}`; });
  const stopNames = services.state(SERVICES, ({ value }) => { names = nmapNames(value); if (latest) draw(); }, () => {});
  const stopStory = services.state(OFFICE, ({ value }) => {
    replay = Boolean(value?.replay);
    for (const label of realLabels) label.textContent = server(replay);
  }, () => {});
  setView('all');
  return () => {
    stopMap();
    stopNames();
    stopStory();
    cleanups.forEach((cleanup) => cleanup());
    root.replaceChildren();
  };
}
