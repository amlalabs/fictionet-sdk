// Test support for the scan panels: a page document, fake page services and
// port maps from a KVM run of the demo. Not served.
import { readFileSync } from 'node:fs';
import { createDocument } from '../../../../dashboard/test-dom.mjs';
import { createSelection } from '../../../../dashboard/selection.mjs';
import * as dom from '../../../../dashboard/dom.mjs';
import * as format from '../../../../dashboard/format.mjs';

// The world's port map after host discovery in the KVM run. That run
// predates banners, so the two banner fields are added here.
export function discoveryMap() {
  const map = JSON.parse(readFileSync(new URL('./data/discovery-ports.json', import.meta.url), 'utf8'));
  return { ...map, untracked_banners: 0, banners: [] };
}

// One open port as nmap's report gives it.
const port = (port, service, product = '', version = '', extra_info = '') => ({ port, protocol: 'tcp', state: 'open', reason: 'syn-ack', service, product, version, extra_info });

// The open TCP ports nmap found and named in the KVM run's SYN scan, by host.
const SCAN = {
  '10.0.0.10': [port(22, 'ssh', 'OpenSSH', '9.2p1 Debian 2+deb12u3', 'protocol 2.0'), port(80, 'http', 'Apache httpd', '2.4.62', '(Debian)')],
  '10.0.0.11': [port(25, 'smtp', 'Postfix smtpd'), port(110, 'pop3', 'Dovecot pop3d'), port(143, 'imap', 'Dovecot imapd')],
  '10.0.0.12': [port(21, 'ftp', 'vsftpd', '3.0.3'), port(22, 'ssh', 'OpenSSH', '9.2p1 Debian 2+deb12u3', 'protocol 2.0')],
  '10.0.0.13': [port(80, 'http', 'lighttpd', '1.4.69', 'Linux'), port(631, 'ipp', 'CUPS', '2.4')],
  '10.0.0.50': [port(22, 'ssh', 'OpenSSH', '9.6p1 Ubuntu 3ubuntu13.20', 'Ubuntu Linux; protocol 2.0'), port(80, 'http', 'nginx', '1.24.0', 'Ubuntu')],
};

// The open port numbers of SCAN, by host.
export const OPEN = Object.fromEntries(Object.entries(SCAN).map(([addr, ports]) => [addr, ports.map((entry) => entry.port)]));

// The discovery map plus a row for ports 1 to `last` on every host, open
// where the SYN scan found them open and closed elsewhere.
export function scannedMap(last = 1024) {
  const map = discoveryMap();
  let revision = map.revision;
  for (const [host, open] of Object.entries(OPEN)) {
    for (let port = 1; port <= last; port++) {
      map.rows.push({ host, port, protocol: 'tcp', state: open.includes(port) ? 'open' : 'closed', first_probe_ms: 50000, last_probe_ms: 50000, probes: 1, revision: ++revision });
    }
  }
  map.revision = revision;
  return map;
}

// nmap's reports in the topic's shape, with values from the KVM run.
export function reports({ os = true, noMatch = null } = {}) {
  const hosts = (ports) => Object.keys(OPEN).map((addr) => ({ addr, state: 'up', reason: 'echo-reply', ports: ports(addr), summarized: [], os: null }));
  const steps = [
    { title: 'Host discovery', args: 'nmap -sn -n -oX notes/office-1.xml 10.0.0.0/24', start: 1792462616, end: 1792462620, elapsed: 3.54, exit: 'success', up: 5, hosts: hosts(() => []) },
    { title: 'SYN scan with service detection', args: 'nmap -sS -sV', start: 1792462622, end: 1792462659, elapsed: 36.36, exit: 'success', up: 5, hosts: hosts((addr) => SCAN[addr]) },
  ];
  if (os) {
    const guesses = {
      '10.0.0.10': ['OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34)', 91],
      '10.0.0.11': ['OpenWrt Kamikaze 7.09 (Linux 2.6.22)', 92],
      '10.0.0.12': ['OpenWrt Kamikaze 7.09 (Linux 2.6.22)', 92],
      '10.0.0.13': ['OpenWrt Kamikaze 7.09 (Linux 2.6.22)', 92],
    };
    // OS detection lists open ports by the name nmap's table gives them, with no product.
    const third = hosts((addr) => SCAN[addr].map((entry) => port(entry.port, entry.service)));
    for (const host of third) {
      if (host.addr === noMatch) host.os = [];
      else if (host.addr === '10.0.0.50') host.os = [{ name: 'Linux 5.0 - 5.5', accuracy: 100 }];
      else host.os = Array.from({ length: 10 }, (_, i) => ({ name: i ? `Guess ${i}` : guesses[host.addr][0], accuracy: guesses[host.addr][1] - (i ? 1 : 0) }));
    }
    steps.push({ title: 'OS detection', args: 'nmap -O', start: 1792462661, end: 1792462670, elapsed: 9, exit: 'success', up: 5, hosts: third });
  }
  return { steps };
}

export const HOSTS = [
  { name: 'workstation', sandbox: 'scanner', status: '/api/state/host-workstation', pinned: true, screen: 'workstation-screen', terminal: 'workstation-terminal' },
  { name: 'office', sandbox: 'server', status: '/api/state/host-office', pinned: true, screen: null, terminal: 'office-terminal' },
];

// Mounts a panel with fake services. `publish(path, value, status)` delivers
// a snapshot to that topic's subscribers.
export function harness(mount, state) {
  const document = createDocument();
  const root = document.createElement('section');
  document.body.append(root);
  const subscribers = new Map();
  const moments = [];
  const selection = createSelection();
  let revision = 0;
  const services = {
    dom,
    format,
    hosts: HOSTS,
    selection,
    moment(element) { moments.push(element); element.classList.add('moment'); },
    state(path, onSnapshot, onError) {
      if (!subscribers.has(path)) subscribers.set(path, new Set());
      const entry = { onSnapshot, onError };
      subscribers.get(path).add(entry);
      return () => subscribers.get(path).delete(entry);
    },
  };
  const dispose = mount(root, services, { state, title: 'Panel', module: '/panels/x.mjs' });
  return {
    document, root, services, moments, selection, dispose, subscribers,
    publish(path, value, status = { too_large: false }) {
      for (const entry of subscribers.get(path) || []) entry.onSnapshot({ revision: ++revision, at: revision, value, status });
    },
    fail(path, error) { for (const entry of subscribers.get(path) || []) entry.onError(error); },
    active() { return [...subscribers.values()].reduce((n, set) => n + set.size, 0); },
    find(selector) { return root.querySelectorAll(selector); },
  };
}

// Text as a reader sees it: separate elements read as separate words, and
// hidden elements not at all.
export function text(node) {
  const words = (item) => (typeof item === 'string' ? item : item.hidden ? '' : item.children.map(words).join(' '));
  return words(node).replace(/\s+/g, ' ').trim();
}
