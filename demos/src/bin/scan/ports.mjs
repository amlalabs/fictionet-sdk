// The Ports panel: for each host that answered, its 1,024 scanned TCP ports
// as a grid that fills in as the world's tap sees nmap's probes and their
// answers. A second view compares only the ports open on any host.
import { element, stylesheet, hosts, ports, counts, openPorts, portState, services as nmapNames, count, limits, server, OFFICE, SERVICES } from './model.mjs';

const LEGEND = [
  ['open', 'open'],
  ['closed', 'closed'],
  ['unreachable', 'unreachable'],
  ['unanswered', 'probed, no answer yet'],
  ['idle', 'not probed'],
];

export function mount(root, services, options) {
  const document = root.ownerDocument;
  const el = (tag, className, text, parent) => element(document, tag, className, text, parent);
  const cleanups = [];
  const on = (node, name, handler) => {
    node.addEventListener(name, handler);
    cleanups.push(() => node.removeEventListener(name, handler));
  };
  stylesheet(document, root);
  const panel = el('div', 'scan-panel ports-panel', undefined, root);
  const bar = el('div', 'ports-bar', undefined, panel);
  const views = el('div', 'segmented', undefined, bar);
  views.setAttribute('role', 'group');
  views.setAttribute('aria-label', 'Ports view');
  const allButton = el('button', '', 'All 1,024 ports', views);
  const openButton = el('button', '', 'Open on any host', views);
  for (const button of [allButton, openButton]) button.setAttribute('type', 'button');
  const legend = el('ul', 'scan-legend', undefined, bar);
  legend.setAttribute('aria-label', 'Port states');
  for (const [state, label] of LEGEND) {
    const item = el('li', '', undefined, legend);
    el('span', 'port-cell', undefined, item).dataset.state = state;
    el('span', '', label, item);
  }
  const notes = el('p', 'loss-note', '', panel);
  notes.setAttribute('role', 'status');
  const empty = el('p', 'empty-note', 'No host has answered yet. Each host gets a row of its 1,024 ports when it answers.', panel);
  const heat = el('div', 'ports-heat', undefined, panel);
  const compare = el('div', 'ports-compare', undefined, panel);

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
  on(allButton, 'click', () => setView('all'));
  on(openButton, 'click', () => setView('open'));

  // One host's row: its name, counts, open ports and the 1,024-cell grid.
  function hostRow(machine) {
    const row = el('section', 'ports-host', undefined, null);
    row.setAttribute('aria-label', `${machine.name} ${machine.addr}`);
    const label = el('div', 'ports-label', undefined, row);
    const title = el('div', 'ports-title', undefined, label);
    el('b', '', machine.name, title);
    el('span', 'office-addr', machine.addr, title);
    const kind = el('span', 'scan-muted', machine.kind === 'real' ? server(replay) : machine.kind === 'simulated' ? 'Simulated' : 'Unnamed address', label);
    if (machine.kind === 'real') realLabels.push(kind);
    const tally = el('p', 'ports-tally', undefined, label);
    const figures = {};
    for (const state of ['open', 'closed', 'unanswered', 'unreachable', 'idle']) {
      const item = el('span', `ports-count is-${state}`, undefined, tally);
      figures[state] = { value: el('b', '', '0', item), name: el('span', '', '', item), item };
    }
    const openList = el('p', 'ports-open', '', label);
    const grid = el('div', 'ports-grid', undefined, row);
    grid.setAttribute('role', 'img');
    const cells = [null];
    for (let port = 1; port <= 1024; port++) {
      const cell = el('span', 'port-cell', undefined, grid);
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
    entry.grid.setAttribute('aria-label', `${entry.machine.addr}: ${count(tally.open, 'open port')}, ${tally.closed.toLocaleString('en-US')} closed, ${tally.idle.toLocaleString('en-US')} not probed`);
    const open = [];
    for (let port = 1; port <= 1024; port++) if (states[port] === 'open') open.push(port);
    entry.openList.replaceChildren();
    if (!open.length) return;
    const named = open.some((port) => names.has(`${entry.machine.addr}:${port}`));
    el('span', 'scan-muted', named ? 'Open · names: nmap says ' : 'Open ', entry.openList);
    for (const port of open) {
      const chip = el('span', 'port-chip', undefined, entry.openList);
      el('b', '', String(port), chip);
      const service = names.get(`${entry.machine.addr}:${port}`);
      if (service) el('span', 'nmap-says', service.service, chip).setAttribute('title', 'nmap says');
    }
  }

  function drawCompare(map) {
    compare.replaceChildren();
    const columns = openPorts(map);
    const machines = hosts(map);
    if (!machines.length) return;
    if (!columns.length) {
      el('p', 'empty-note', 'No port is open on any host yet.', compare);
      return;
    }
    el('p', 'scan-muted ports-compare-note', `The ${count(columns.length, 'TCP port')} open on any host. Under each open port, the service name nmap says.`, compare);
    const table = el('table', 'data-table ports-matrix', undefined, compare);
    const head = el('tr', '', undefined, el('thead', '', undefined, table));
    el('th', '', 'Host', head).setAttribute('scope', 'col');
    for (const port of columns) el('th', 'ports-matrix-port', String(port), head).setAttribute('scope', 'col');
    const body = el('tbody', '', undefined, table);
    const words = { idle: 'not probed', unanswered: 'no answer yet' };
    for (const machine of machines) {
      const tr = el('tr', '', undefined, body);
      const th = el('th', '', undefined, tr);
      th.setAttribute('scope', 'row');
      el('b', '', machine.name, th);
      el('span', 'office-addr', machine.addr, th);
      for (const port of columns) {
        const state = portState(map, machine.addr, port);
        const td = el('td', 'ports-matrix-cell', undefined, tr);
        td.dataset.state = state;
        const service = state === 'open' && names.get(`${machine.addr}:${port}`);
        td.setAttribute('title', `${port}/tcp ${words[state] || state}${service ? `, nmap says ${service.service}` : ''}`);
        const mark = el('span', 'port-cell', undefined, td);
        mark.dataset.state = state;
        mark.setAttribute('role', 'img');
        mark.setAttribute('aria-label', words[state] || state);
        if (service) el('span', 'nmap-says', service.service, td);
      }
    }
  }

  function draw() {
    const map = latest?.value;
    const machines = hosts(map);
    empty.hidden = machines.length > 0;
    notes.textContent = limits(latest).join(' ');
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
