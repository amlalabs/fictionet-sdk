// What the scan panels show, computed only from the world's port map and
// nmap's reports. The panels import this module from /assets/scan/.

// The page topics, by panel title.
export const PORTS = '/api/state/ports';
export const SERVICES = '/api/state/services';
export const OFFICE = '/api/state/office';

// Port row states as the world's tap names them, and "idle" for no probe.
export const STATES = ['open', 'closed', 'unreachable', 'unanswered', 'idle'];

// Loads the panels' stylesheet inside a panel root, with the page's `el`.
export function stylesheet(el, root) {
  return el('link', { rel: 'stylesheet', href: '/assets/scan/scan.css' }, root);
}

const answered = (state) => state === 'open' || state === 'closed';

// The last octet of an address in 10.0.0.0/24, or null outside it.
export function office(addr) {
  const parts = String(addr).split('.').map(Number);
  return parts.length === 4 && parts[0] === 10 && parts[1] === 0 && parts[2] === 0 && parts[3] >= 0 && parts[3] <= 255 ? parts[3] : null;
}

// The 256 addresses of 10.0.0.0/24: "host" once any probe got an answer,
// "empty" when probes only came back unreachable, "waiting" while probes
// have no answer yet, "idle" before any probe.
export function addresses(map) {
  const cells = new Array(256).fill('idle');
  const rank = { idle: 0, waiting: 1, empty: 2, host: 3 };
  for (const row of map?.rows || []) {
    const last = office(row.host);
    if (last === null) continue;
    const state = answered(row.state) ? 'host' : row.state === 'unreachable' ? 'empty' : 'waiting';
    if (rank[state] > rank[cells[last]]) cells[last] = state;
  }
  return cells;
}

// Addresses probed, hosts answering and open TCP ports.
export function summary(map) {
  const cells = addresses(map);
  return {
    probed: cells.filter((cell) => cell !== 'idle').length,
    answering: cells.filter((cell) => cell === 'host').length,
    open: (map?.rows || []).filter((row) => row.protocol === 'tcp' && row.state === 'open').length,
  };
}

// The machines whose address has an answered row, in address order, with
// any answering address the world does not name.
export function hosts(map) {
  const cells = addresses(map);
  const named = new Map((map?.machines || []).map((machine) => [machine.addr, machine]));
  const found = [];
  cells.forEach((cell, last) => {
    if (cell !== 'host') return;
    const addr = `10.0.0.${last}`;
    found.push(named.get(addr) || { name: addr, addr, kind: 'unnamed' });
  });
  return found;
}

// Each scanned TCP port from 1 to 1,024 on one host, as a state name.
export function ports(map, host) {
  const states = new Array(1025).fill('idle');
  for (const row of map?.rows || []) {
    if (row.host === host && row.protocol === 'tcp' && row.port >= 1 && row.port <= 1024) states[row.port] = row.state;
  }
  return states;
}

// How many ports are in each state.
export function counts(states) {
  const total = Object.fromEntries(STATES.map((state) => [state, 0]));
  for (let port = 1; port < states.length; port++) total[states[port]]++;
  return total;
}

// TCP ports open on any host, in order.
export function openPorts(map) {
  const open = new Set();
  for (const row of map?.rows || []) if (row.protocol === 'tcp' && row.state === 'open') open.add(row.port);
  return [...open].sort((a, b) => a - b);
}

// The state of one TCP port on one host, as the map has it.
export function portState(map, host, port) {
  return (map?.rows || []).find((row) => row.host === host && row.protocol === 'tcp' && row.port === port)?.state || 'idle';
}

// nmap's name for each port it listed open. A step that named a product
// (service detection) wins over a later one that only named the service
// from its port number (OS detection).
export function services(reports) {
  const named = new Map();
  for (const step of reports?.steps || []) {
    for (const host of step.hosts || []) {
      for (const port of host.ports || []) {
        if (port.protocol !== 'tcp' || port.state !== 'open' || !port.service) continue;
        const key = `${host.addr}:${port.port}`;
        const known = named.get(key);
        if (!known || (!known.product && !known.version) || port.product || port.version) named.set(key, port);
      }
    }
  }
  return named;
}

// nmap's OS result for a host: null before any OS detection, else the best
// guess, its accuracy and how many others nmap gave, or none.
export function osGuess(reports, host) {
  let result = null;
  for (const step of reports?.steps || []) {
    const entry = (step.hosts || []).find((item) => item.addr === host);
    if (!entry || entry.os === null || entry.os === undefined) continue;
    const [best, ...rest] = entry.os;
    result = best ? { name: best.name, accuracy: best.accuracy, more: rest.length } : { none: true };
  }
  return result;
}

// nmap's product, version and extra details joined as nmap prints them.
export function version(port) {
  return [port.version, port.extra_info ? `(${port.extra_info})` : ''].filter(Boolean).join(' ');
}

// The banner kept for each host and port.
export function banners(map) {
  return new Map((map?.banners || []).map((banner) => [`${banner.host}:${banner.port}`, banner]));
}

// What the page calls the office server: the real VM, or in a replay
// without VMs, the in-world stand-in that answers for it.
export function server(replay) {
  return replay ? 'Stand-in for the Ubuntu VM' : 'Real Ubuntu VM';
}

// Why the panels may show less than the world saw. `plural` is the page's
// services.format.plural.
export function limits(snapshot, plural) {
  const map = snapshot?.value;
  const notes = [];
  if (snapshot?.status?.too_large) notes.push('The port map passed its size limit. The last complete map is shown.');
  if (map?.untracked) notes.push(`The port map is full at ${plural(map.max_rows, 'row')}. ${plural(map.untracked, 'later probe')} to new ports ${map.untracked === 1 ? 'is' : 'are'} not shown.`);
  return notes;
}
