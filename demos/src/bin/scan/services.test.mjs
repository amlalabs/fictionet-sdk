import test from 'node:test';
import assert from 'node:assert/strict';
import { mount } from './services.mjs';
import { OFFICE, PORTS, SERVICES, services, osGuess, addresses, office } from './model.mjs';
import { harness, discoveryMap, scannedMap, reports, text } from './panel-harness.mjs';

const BANNERS = [
  { host: '10.0.0.10', port: 22, text: 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3', server: null, at_ms: 60000, revision: 9000 },
  { host: '10.0.0.10', port: 80, text: 'HTTP/1.0 200 OK', server: 'Apache/2.4.62 (Debian)', at_ms: 60100, revision: 9001 },
  { host: '10.0.0.50', port: 22, text: 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20', server: null, at_ms: 61000, revision: 9002 },
  { host: '10.0.0.50', port: 80, text: 'HTTP/1.1 200 OK', server: 'nginx/1.24.0 (Ubuntu)', at_ms: 61100, revision: 9003 },
];

function group(f, addr) {
  return f.find('tbody').find((body) => text(body.querySelectorAll('th')[0]).includes(addr));
}

test('one row per open port with the wire banner beside nmap name product and version', () => {
  const f = harness(mount, SERVICES);
  f.publish(PORTS, { ...scannedMap(), banners: BANNERS });
  f.publish(SERVICES, reports());
  const head = f.find('thead')[0].querySelectorAll('tr');
  assert.deepEqual(head[0].querySelectorAll('th').map(text), ['', 'nmap says']);
  assert.equal(head[0].querySelectorAll('th')[1].getAttribute('colspan'), '3');
  assert.deepEqual(head[1].querySelectorAll('th').map(text), ['Port', 'Banner on the wire', 'Service', 'Product', 'Version']);
  const server = group(f, '10.0.0.50');
  const rows = server.querySelectorAll('tr').slice(1);
  assert.deepEqual(rows.map((row) => row.querySelectorAll('td').map(text)), [
    ['22/tcp', 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20', 'ssh', 'OpenSSH', '9.6p1 Ubuntu 3ubuntu13.20 (Ubuntu Linux; protocol 2.0)'],
    ['80/tcp', 'HTTP/1.1 200 OK Server: nginx/1.24.0 (Ubuntu)', 'http', 'nginx', '1.24.0 (Ubuntu)'],
  ]);
  for (const row of rows) {
    for (const cell of row.querySelectorAll('td').slice(2)) assert.equal(cell.getAttribute('title'), 'nmap says');
  }
  assert.equal(text(group(f, '10.0.0.11').querySelectorAll('tr')[1].querySelectorAll('td')[1]), 'none seen yet');
  assert.equal(f.find('tbody').length, 5);
  assert.equal(f.find('tbody').reduce((n, body) => n + body.querySelectorAll('tr').length - 1, 0), 11);
  f.dispose();
});

test('each host shows nmap OS guess with its accuracy or that nmap made no match', () => {
  const f = harness(mount, SERVICES);
  f.publish(PORTS, scannedMap());
  f.publish(SERVICES, reports({ os: false }));
  assert.equal(text(group(f, '10.0.0.10').querySelectorAll('.services-os')[0]), 'OS detection has not run yet');
  f.publish(SERVICES, reports({ noMatch: '10.0.0.13' }));
  assert.equal(text(group(f, '10.0.0.10').querySelectorAll('.services-os')[0]), 'nmap says OpenWrt 0.9 - 7.09 (Linux 2.4.30 - 2.4.34) · 91% · 9 other guesses');
  assert.equal(text(group(f, '10.0.0.50').querySelectorAll('.services-os')[0]), 'nmap says Linux 5.0 - 5.5 · 100%');
  assert.equal(text(group(f, '10.0.0.13').querySelectorAll('.services-os')[0]), 'nmap made no match');
  assert.match(text(group(f, '10.0.0.50').querySelectorAll('th')[0]), /^server 10\.0\.0\.50 Real Ubuntu VM/);
  assert.match(text(group(f, '10.0.0.10').querySelectorAll('th')[0]), /^www 10\.0\.0\.10 Simulated by the world/);
  f.dispose();
});

test('the port service detection named wins over the later OS step table name', () => {
  const named = services(reports());
  assert.equal(named.get('10.0.0.50:22').product, 'OpenSSH');
  const os = reports();
  os.steps.splice(1, 1);
  assert.equal(services(os).get('10.0.0.50:22').product, '');
  assert.equal(services(os).get('10.0.0.50:22').service, 'ssh');
  assert.equal(osGuess(reports(), '10.0.0.12').more, 9);
  assert.equal(osGuess(reports({ os: false }), '10.0.0.12'), null);
  assert.deepEqual(osGuess(reports({ noMatch: '10.0.0.12' }), '10.0.0.12'), { none: true });
});

test('addresses rank an answer above unreachable above no answer', () => {
  const rows = [
    { host: '10.0.0.7', port: 0, protocol: 'icmp', state: 'unanswered' },
    { host: '10.0.0.7', port: 443, protocol: 'tcp', state: 'unreachable' },
    { host: '10.0.0.8', port: 443, protocol: 'tcp', state: 'unreachable' },
    { host: '10.0.0.8', port: 0, protocol: 'icmp', state: 'closed' },
    { host: '10.0.0.9', port: 0, protocol: 'icmp', state: 'unanswered' },
    { host: '10.0.1.9', port: 0, protocol: 'icmp', state: 'open' },
  ];
  const cells = addresses({ rows });
  assert.deepEqual([cells[7], cells[8], cells[9], cells[10]], ['empty', 'host', 'waiting', 'idle']);
  assert.equal(cells.filter((cell) => cell === 'host').length, 1);
  assert.equal(office('10.0.1.9'), null);
  assert.equal(office('10.0.0.255'), 255);
});

test('hostile banners and nmap strings are set as text', () => {
  const f = harness(mount, SERVICES);
  f.publish(PORTS, { ...scannedMap(), banners: [{ host: '10.0.0.10', port: 22, text: '<img src=x onerror=alert(1)>', server: '<script>x</script>', at_ms: 1, revision: 1 }] });
  const reported = reports();
  reported.steps[1].hosts[0].ports[0].product = '<i>OpenSSH</i>';
  reported.steps[2].hosts[0].os[0].name = '<b>Linux</b>';
  f.publish(SERVICES, reported);
  assert.equal(f.find('img').length + f.find('script').length + f.find('i').length, 0);
  const row = group(f, '10.0.0.10').querySelectorAll('tr')[1].querySelectorAll('td');
  assert.equal(text(row[1]), '<img src=x onerror=alert(1)> Server: <script>x</script>');
  assert.equal(text(row[3]), '<i>OpenSSH</i>');
  assert.match(text(group(f, '10.0.0.10').querySelectorAll('.services-os')[0]), /<b>Linux<\/b>/);
  f.dispose();
});

test('before the scan the panel waits, and limits are stated', () => {
  const f = harness(mount, SERVICES);
  f.publish(PORTS, { ...discoveryMap(), rows: [] });
  assert.equal(f.find('.empty-note')[0].hidden, false);
  assert.equal(f.find('table')[0].hidden, true);
  f.publish(PORTS, { ...discoveryMap(), untracked_banners: 2 }, { too_large: true });
  assert.equal(f.find('table')[0].hidden, false);
  assert.match(f.find('.loss-note')[0].textContent, /port map passed its size limit.*2 banners did not fit; the map keeps 1,024 banners\./);
  assert.equal(text(group(f, '10.0.0.10').querySelectorAll('tr')[1]), 'No open port seen yet.');
  f.dispose();
});

test('a redraw happens only when what the panel shows changes', () => {
  const f = harness(mount, SERVICES);
  const map = scannedMap();
  f.publish(PORTS, map);
  const first = f.find('tbody')[0];
  f.publish(PORTS, { ...map, revision: map.revision + 1, at_ms: map.at_ms + 5 });
  assert.equal(f.find('tbody')[0], first);
  f.publish(PORTS, { ...map, banners: BANNERS });
  assert.notEqual(f.find('tbody')[0], first);
  f.dispose();
});

test('a replay labels nmap as a recorded report and the server as a stand-in', () => {
  const f = harness(mount, SERVICES);
  f.publish(PORTS, { ...scannedMap(), banners: BANNERS });
  f.publish(SERVICES, reports());
  f.publish(OFFICE, { steps: [], replay: true });
  assert.equal(text(f.find('thead')[0].querySelectorAll('th')[1]), 'nmap says · recorded report');
  assert.match(text(group(f, '10.0.0.50').querySelectorAll('th')[0]), /^server 10\.0\.0\.50 Stand-in for the Ubuntu VM/);
  f.publish(OFFICE, { steps: [], replay: false });
  assert.equal(text(f.find('thead')[0].querySelectorAll('th')[1]), 'nmap says');
  assert.match(text(group(f, '10.0.0.50').querySelectorAll('th')[0]), /^server 10\.0\.0\.50 Real Ubuntu VM/);
  f.dispose();
});

test('dispose releases its subscriptions', () => {
  const f = harness(mount, SERVICES);
  assert.equal(f.active(), 3);
  f.dispose();
  assert.equal(f.active(), 0);
  assert.equal(f.root.children.length, 0);
});
