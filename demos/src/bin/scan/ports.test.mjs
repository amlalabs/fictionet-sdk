import test from 'node:test';
import assert from 'node:assert/strict';
import { mount } from './ports.mjs';
import { PORTS, SERVICES } from './model.mjs';
import { harness, discoveryMap, scannedMap, reports, text } from './panel-harness.mjs';

function host(f, addr) {
  return f.find('.ports-host').find((row) => row.getAttribute('aria-label').endsWith(addr));
}
function cells(row) {
  return row.querySelectorAll('.ports-grid')[0].querySelectorAll('.port-cell');
}

test('before any host answers the panel says so and the legend names every state', () => {
  const f = harness(mount, PORTS);
  f.publish(PORTS, { ...discoveryMap(), rows: [] });
  assert.equal(f.find('.ports-host').length, 0);
  assert.equal(f.find('.empty-note')[0].hidden, false);
  const legend = f.find('.scan-legend')[0].querySelectorAll('li');
  assert.deepEqual(legend.map((item) => item.querySelectorAll('.port-cell')[0].dataset.state), ['open', 'closed', 'unreachable', 'unanswered', 'idle']);
  assert.deepEqual(legend.map(text), ['open', 'closed', 'unreachable', 'probed, no answer yet', 'not probed']);
  f.dispose();
});

test('each answering host gets 1,024 cells whose states and counts follow the map', () => {
  const f = harness(mount, PORTS);
  f.publish(PORTS, discoveryMap());
  assert.equal(f.find('.empty-note')[0].hidden, true);
  assert.deepEqual(f.find('.ports-host').map((row) => row.getAttribute('aria-label')), ['www 10.0.0.10', 'mail 10.0.0.11', 'files 10.0.0.12', 'printer 10.0.0.13', 'server 10.0.0.50']);
  const server = host(f, '10.0.0.50');
  assert.equal(cells(server).length, 1024);
  assert.ok(cells(server).every((cell) => cell.dataset.state === 'idle'));
  assert.match(text(server), /0 open 0 closed 1,024 not probed/);
  assert.match(text(server), /Real Ubuntu VM/);

  const map = scannedMap(512);
  map.rows.push({ host: '10.0.0.50', port: 600, protocol: 'tcp', state: 'unanswered', first_probe_ms: 1, last_probe_ms: 1, probes: 1, revision: 1 });
  f.publish(PORTS, map);
  const grid = cells(server);
  assert.equal(grid[21].dataset.state, 'open');
  assert.equal(grid[21].getAttribute('title'), '22/tcp open');
  assert.equal(grid[0].dataset.state, 'closed');
  assert.equal(grid[599].dataset.state, 'unanswered');
  assert.equal(grid[700].dataset.state, 'idle');
  assert.match(text(server), /2 open 510 closed 1 no answer 511 not probed/);
  assert.deepEqual(server.querySelectorAll('.port-chip').map(text), ['22', '80']);
  assert.match(text(server.querySelectorAll('.ports-open')[0]), /^Open 22 80$/);
  f.dispose();
});

test('counts and cells update in place as the scan fills in', () => {
  const f = harness(mount, PORTS);
  f.publish(PORTS, scannedMap(100));
  const mail = host(f, '10.0.0.11');
  const cell = cells(mail)[500];
  const figure = mail.querySelectorAll('.ports-count')[1].querySelectorAll('b')[0];
  assert.equal(figure.textContent, '99');
  f.publish(PORTS, scannedMap());
  assert.equal(host(f, '10.0.0.11'), mail);
  assert.equal(cells(mail)[500], cell);
  assert.equal(cell.dataset.state, 'closed');
  assert.equal(mail.querySelectorAll('.ports-count')[1].querySelectorAll('b')[0], figure);
  assert.equal(figure.textContent, '1,021');
  f.dispose();
});

test('open ports carry the names nmap says once its report arrives', () => {
  const f = harness(mount, PORTS);
  f.publish(PORTS, scannedMap());
  f.publish(SERVICES, reports());
  const www = host(f, '10.0.0.10');
  const open = www.querySelectorAll('.ports-open')[0];
  assert.equal(text(open), 'Open · names: nmap says 22 ssh 80 http');
  for (const name of open.querySelectorAll('.nmap-says')) assert.equal(name.getAttribute('title'), 'nmap says');
  f.dispose();
});

test('the comparison view lists only ports open on any host, with nmap names under them', () => {
  const f = harness(mount, PORTS);
  f.publish(PORTS, scannedMap());
  f.publish(SERVICES, reports());
  const [all, open] = f.find('.segmented')[0].querySelectorAll('button');
  assert.equal(all.getAttribute('aria-pressed'), 'true');
  open.click();
  assert.equal(open.getAttribute('aria-pressed'), 'true');
  assert.equal(f.find('.ports-heat')[0].hidden, true);
  const table = f.find('.ports-compare')[0];
  assert.match(text(table), /The 7 TCP ports open on any host\. Under each open port, the service name nmap says\./);
  const head = table.querySelectorAll('thead')[0].querySelectorAll('th').map(text);
  assert.deepEqual(head, ['Host', '21', '22', '25', '80', '110', '143', '631']);
  const rows = table.querySelectorAll('tbody')[0].querySelectorAll('tr');
  assert.equal(rows.length, 5);
  const printer = rows[3].querySelectorAll('td');
  assert.deepEqual(printer.map((cell) => cell.dataset.state), ['closed', 'closed', 'closed', 'open', 'closed', 'closed', 'open']);
  assert.equal(printer[6].getAttribute('title'), '631/tcp open, nmap says ipp');
  assert.equal(printer[0].getAttribute('title'), '21/tcp closed');
  assert.equal(text(printer[6]), 'ipp');
  all.click();
  assert.equal(f.find('.ports-heat')[0].hidden, false);
  f.dispose();
});

test('the bound and a refused publication are stated', () => {
  const f = harness(mount, PORTS);
  f.publish(PORTS, { ...scannedMap(10), untracked: 1 }, { too_large: true });
  assert.match(f.find('.loss-note')[0].textContent, /passed its size limit.*full at 16,384 rows\. 1 later probe to new ports is not shown\./);
  f.dispose();
});

test('names from the world are set as text', () => {
  const f = harness(mount, PORTS);
  const map = scannedMap(30);
  map.machines[1].name = '<script>alert(1)</script>';
  f.publish(PORTS, map);
  const reported = reports();
  reported.steps[1].hosts[0].ports[0].service = '<b>ssh</b>';
  f.publish(SERVICES, reported);
  assert.equal(f.find('script').length + f.find('b').filter((b) => b.textContent === 'ssh').length, 0);
  assert.equal(host(f, '10.0.0.11').getAttribute('aria-label'), '<script>alert(1)</script> 10.0.0.11');
  assert.equal(host(f, '10.0.0.10').querySelectorAll('.nmap-says')[0].textContent, '<b>ssh</b>');
  f.dispose();
});

test('dispose releases subscriptions and the view buttons', () => {
  const f = harness(mount, PORTS);
  const buttons = f.find('.segmented')[0].querySelectorAll('button');
  assert.equal(f.active(), 2);
  assert.ok(buttons.every((button) => button.listenerCount === 1));
  f.dispose();
  assert.equal(f.active(), 0);
  assert.ok(buttons.every((button) => button.listenerCount === 0));
  assert.equal(f.root.children.length, 0);
});
