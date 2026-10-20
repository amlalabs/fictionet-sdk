// The Services panel: one row per open port, with the banner the world's
// tap saw on the wire beside nmap's name, product and version, and nmap's
// OS guess for each host. Everything from nmap is labeled "nmap says".
import { element, stylesheet, hosts, services as nmapNames, osGuess, version, banners as wireBanners, count, PORTS } from './model.mjs';

export function mount(root, services, options) {
  const document = root.ownerDocument;
  const el = (tag, className, text, parent) => element(document, tag, className, text, parent);
  stylesheet(document, root);
  const panel = el('div', 'scan-panel services-panel', undefined, root);
  el('p', 'scan-muted services-intro', 'A banner is the first data an open port sent to the scanner, as the world saw it on the wire. Service names, versions and OS guesses are what nmap says.', panel);
  const notes = el('p', 'loss-note', '', panel);
  notes.setAttribute('role', 'status');
  const empty = el('p', 'empty-note', 'No host has answered yet. Each open port gets a row as nmap finds it.', panel);
  const table = el('table', 'data-table services-table', undefined, panel);
  const head = el('thead', '', undefined, table);
  const groupRow = el('tr', 'services-group-row', undefined, head);
  el('th', '', '', groupRow).setAttribute('colspan', '2');
  const nmapHead = el('th', 'nmap-says', 'nmap says', groupRow);
  nmapHead.setAttribute('colspan', '3');
  nmapHead.setAttribute('scope', 'colgroup');
  const labels = el('tr', '', undefined, head);
  for (const label of ['Port', 'Banner on the wire', 'Service', 'Product', 'Version']) el('th', '', label, labels).setAttribute('scope', 'col');
  let map = null, reports = null, mapStatus = null, reportStatus = null, drawn = '';
  const seen = new Set();

  function osLine(parent, addr) {
    const guess = osGuess(reports, addr);
    const line = el('span', 'services-os', undefined, parent);
    if (!guess) {
      el('span', 'scan-muted', 'OS detection has not run yet', line);
      return;
    }
    el('span', 'nmap-says', guess.none ? 'nmap made no match' : 'nmap says', line);
    if (guess.none) return;
    el('b', 'services-os-name', ` ${guess.name}`, line);
    el('span', 'scan-muted', ` · ${guess.accuracy}%${guess.more ? ` · ${count(guess.more, 'other guess', 'other guesses')}` : ''}`, line);
  }

  function draw() {
    const machines = hosts(map);
    const names = nmapNames(reports);
    const kept = wireBanners(map);
    const notesText = [];
    if (mapStatus?.too_large) notesText.push('The port map passed its size limit. The last complete map is shown.');
    if (reportStatus?.too_large) notesText.push('nmap\'s reports passed their size limit. The last complete reports are shown.');
    if (map?.untracked_banners) notesText.push(`${count(map.untracked_banners, 'banner')} did not fit; the map keeps ${count(1024, 'banner')}.`);
    notes.textContent = notesText.join(' ');
    empty.hidden = machines.length > 0;
    table.hidden = machines.length === 0;
    // The port map changes several times a second while nmap probes; redraw
    // only when something this panel shows has changed.
    const open = new Map(machines.map((machine) => [machine.addr, new Set()]));
    for (const row of map?.rows || []) if (row.protocol === 'tcp' && row.state === 'open') open.get(row.host)?.add(row.port);
    for (const key of names.keys()) {
      const [addr, port] = key.split(':');
      open.get(addr)?.add(Number(port));
    }
    const shown = JSON.stringify([machines, [...open].map(([addr, ports]) => [addr, [...ports]]), [...kept.values()], [...names.entries()], machines.map((m) => osGuess(reports, m.addr))]);
    if (shown === drawn) return;
    drawn = shown;
    for (const body of table.querySelectorAll('tbody')) body.remove();
    for (const machine of machines) {
      const body = el('tbody', 'services-host', undefined, table);
      const top = el('tr', 'services-host-row', undefined, body);
      const cell = el('th', '', undefined, top);
      cell.setAttribute('colspan', '5');
      cell.setAttribute('scope', 'rowgroup');
      const title = el('span', 'ports-title', undefined, cell);
      el('b', '', machine.name, title);
      el('span', 'office-addr', machine.addr, title);
      el('span', machine.kind === 'real' ? 'scan-badge' : 'scan-muted', machine.kind === 'real' ? 'Real Ubuntu VM' : machine.kind === 'simulated' ? 'Simulated by the world' : 'Not one of the world\'s machines', title);
      osLine(cell, machine.addr);
      const ports = [...open.get(machine.addr)].sort((a, b) => a - b);
      if (!ports.length) {
        const none = el('tr', '', undefined, body);
        el('td', 'scan-muted', 'No open port seen yet.', none).setAttribute('colspan', '5');
        continue;
      }
      for (const port of ports) {
        const key = `${machine.addr}:${port}`;
        const tr = el('tr', '', undefined, body);
        if (!seen.has(key)) {
          seen.add(key);
          tr.classList.add('new-row');
        }
        el('td', 'numeric services-port', `${port}/tcp`, tr);
        const banner = kept.get(key);
        const wire = el('td', 'services-banner', undefined, tr);
        if (banner) {
          el('span', 'services-banner-text', banner.text, wire);
          if (banner.server) el('span', 'services-banner-server', `Server: ${banner.server}`, wire);
        } else {
          el('span', 'scan-muted', 'none seen yet', wire);
        }
        const named = names.get(key);
        for (const value of [named?.service, named?.product, named && version(named)]) {
          el('td', 'services-nmap', value || '—', tr).setAttribute('title', 'nmap says');
        }
      }
    }
  }

  const stopReports = services.state(options.state, (snapshot) => { reports = snapshot.value; reportStatus = snapshot.status; draw(); }, (error) => { notes.textContent = `Could not load nmap's reports: ${error.message}`; });
  const stopMap = services.state(PORTS, (snapshot) => { map = snapshot.value; mapStatus = snapshot.status; draw(); }, (error) => { notes.textContent = `Could not load the port map: ${error.message}`; });
  draw();
  return () => {
    stopReports();
    stopMap();
    root.replaceChildren();
  };
}
