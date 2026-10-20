// The Services panel: one row per open port, with the banner the world's
// tap saw on the wire beside nmap's name, product and version, and nmap's
// OS guess for each host. Everything from nmap is labeled "nmap says".
import { stylesheet, hosts, services as nmapNames, osGuess, version, banners as wireBanners, server, OFFICE, PORTS } from './model.mjs';

export function mount(root, services, options) {
  const { el } = services.dom.scoped(root);
  const { plural } = services.format;
  stylesheet(el, root);
  const panel = el('div', { class: 'scan-panel services-panel' }, root);
  el('p', { class: 'scan-muted services-intro', text: 'A banner is the first data an open port sent to the scanner, as the world saw it on the wire. Service names, versions and OS guesses are what nmap says.' }, panel);
  const notes = el('p', { class: 'loss-note' }, panel);
  notes.setAttribute('role', 'status');
  const empty = el('p', { class: 'empty-note', text: 'No host has answered yet. Each open port gets a row as nmap finds it.' }, panel);
  const table = el('table', { class: 'data-table services-table' }, panel);
  const head = el('thead', {}, table);
  const groupRow = el('tr', { class: 'services-group-row' }, head);
  el('th', {}, groupRow).setAttribute('colspan', '2');
  const nmapHead = el('th', { class: 'nmap-says', text: 'nmap says' }, groupRow);
  nmapHead.setAttribute('colspan', '3');
  nmapHead.setAttribute('scope', 'colgroup');
  const labels = el('tr', {}, head);
  for (const label of ['Port', 'Banner on the wire', 'Service', 'Product', 'Version']) el('th', { text: label }, labels).setAttribute('scope', 'col');
  let map = null, reports = null, mapStatus = null, reportStatus = null, replay = false, drawn = '';
  const seen = new Set();

  function osLine(parent, addr) {
    const guess = osGuess(reports, addr);
    const line = el('span', { class: 'services-os' }, parent);
    if (!guess) {
      el('span', { class: 'scan-muted', text: 'OS detection has not run yet' }, line);
      return;
    }
    el('span', { class: 'nmap-says', text: guess.none ? 'nmap made no match' : 'nmap says' }, line);
    if (guess.none) return;
    el('b', { class: 'services-os-name', text: ` ${guess.name}` }, line);
    el('span', { class: 'scan-muted', text: ` · ${guess.accuracy}%${guess.more ? ` · ${plural(guess.more, 'other guess', 'other guesses')}` : ''}` }, line);
  }

  function draw() {
    const machines = hosts(map);
    const names = nmapNames(reports);
    const kept = wireBanners(map);
    const notesText = [];
    if (mapStatus?.too_large) notesText.push('The port map passed its size limit. The last complete map is shown.');
    if (reportStatus?.too_large) notesText.push('nmap\'s reports passed their size limit. The last complete reports are shown.');
    if (map?.untracked_banners) notesText.push(`${plural(map.untracked_banners, 'banner')} did not fit; the map keeps ${plural(1024, 'banner')}.`);
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
    nmapHead.textContent = replay ? 'nmap says · recorded report' : 'nmap says';
    const shown = JSON.stringify([replay, machines, [...open].map(([addr, ports]) => [addr, [...ports]]), [...kept.values()], [...names.entries()], machines.map((m) => osGuess(reports, m.addr))]);
    if (shown === drawn) return;
    drawn = shown;
    for (const body of table.querySelectorAll('tbody')) body.remove();
    for (const machine of machines) {
      const body = el('tbody', { class: 'services-host' }, table);
      const top = el('tr', { class: 'services-host-row' }, body);
      const cell = el('th', {}, top);
      cell.setAttribute('colspan', '5');
      cell.setAttribute('scope', 'rowgroup');
      const title = el('span', { class: 'ports-title' }, cell);
      el('b', { text: machine.name }, title);
      el('span', { class: 'office-addr', text: machine.addr }, title);
      el('span', { class: machine.kind === 'real' ? 'scan-badge' : 'scan-muted', text: machine.kind === 'real' ? server(replay) : machine.kind === 'simulated' ? 'Simulated by the world' : 'Not one of the world\'s machines' }, title);
      osLine(cell, machine.addr);
      const ports = [...open.get(machine.addr)].sort((a, b) => a - b);
      if (!ports.length) {
        const none = el('tr', {}, body);
        el('td', { class: 'scan-muted', text: 'No open port seen yet.' }, none).setAttribute('colspan', '5');
        continue;
      }
      for (const port of ports) {
        const key = `${machine.addr}:${port}`;
        const tr = el('tr', {}, body);
        if (!seen.has(key)) {
          seen.add(key);
          tr.classList.add('new-row');
        }
        el('td', { class: 'numeric services-port', text: `${port}/tcp` }, tr);
        const banner = kept.get(key);
        const wire = el('td', { class: 'services-banner' }, tr);
        if (banner) {
          el('span', { class: 'services-banner-text', text: banner.text }, wire);
          if (banner.server) el('span', { class: 'services-banner-server', text: `Server: ${banner.server}` }, wire);
        } else {
          el('span', { class: 'scan-muted', text: 'none seen yet' }, wire);
        }
        const named = names.get(key);
        for (const value of [named?.service, named?.product, named && version(named)]) {
          el('td', { class: 'services-nmap', text: value || '—' }, tr).setAttribute('title', 'nmap says');
        }
      }
    }
  }

  const stopReports = services.state(options.state, (snapshot) => { reports = snapshot.value; reportStatus = snapshot.status; draw(); }, (error) => { notes.textContent = `Could not load nmap's reports: ${error.message}`; });
  const stopMap = services.state(PORTS, (snapshot) => { map = snapshot.value; mapStatus = snapshot.status; draw(); }, (error) => { notes.textContent = `Could not load the port map: ${error.message}`; });
  const stopStory = services.state(OFFICE, ({ value }) => { replay = Boolean(value?.replay); draw(); }, () => {});
  draw();
  return () => {
    stopReports();
    stopMap();
    stopStory();
    root.replaceChildren();
  };
}
