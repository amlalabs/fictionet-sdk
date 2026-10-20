import test from 'node:test';
import assert from 'node:assert/strict';
import { mount } from './office.mjs';
import { PORTS } from './model.mjs';
import { harness, discoveryMap, scannedMap, text } from './panel-harness.mjs';

const OFFICE = '/api/state/office';

function story(states, exits = []) {
  const commands = ['sudo nmap -sn -n -oX notes/office-1.xml 10.0.0.0/24', 'sudo nmap -sS -sV', 'sudo nmap -O'];
  return { steps: ['Host discovery', 'SYN scan with service detection', 'OS detection'].map((title, i) => ({ title, command: commands[i], state: states[i], exit: exits[i] ?? null })) };
}

function grid(f) {
  return f.find('.office-grid')[0].querySelectorAll('.office-cell');
}

test('the recorded discovery map lights five hosts and leaves the rest without a host', () => {
  const f = harness(mount, OFFICE);
  f.publish(PORTS, discoveryMap());
  const cells = grid(f);
  assert.equal(cells.length, 256);
  const hosts = cells.map((cell, i) => [i, cell.dataset.state]).filter(([, state]) => state === 'host').map(([i]) => i);
  assert.deepEqual(hosts, [10, 11, 12, 13, 50]);
  assert.equal(cells.filter((cell) => cell.dataset.state === 'empty').length, 251);
  assert.equal(cells[50].getAttribute('title'), '10.0.0.50: a host answered');
  assert.equal(cells[14].getAttribute('title'), '10.0.0.14: no host (unreachable)');
  assert.equal(text(f.find('.office-summary')[0]), '256 addresses probed 5 hosts answering 0 open ports');
  f.dispose();
});

test('a half done sweep leaves later addresses unprobed and marks unanswered probes', () => {
  const f = harness(mount, OFFICE);
  const map = discoveryMap();
  map.rows = map.rows.filter((row) => Number(row.host.split('.')[3]) < 128);
  map.rows.push({ host: '10.0.0.127', port: 0, protocol: 'icmp', state: 'unanswered', first_probe_ms: 1, last_probe_ms: 1, probes: 1, revision: 1 });
  map.rows = map.rows.filter((row) => !(row.host === '10.0.0.127' && row.state !== 'unanswered'));
  f.publish(PORTS, map);
  const cells = grid(f);
  assert.equal(cells[127].dataset.state, 'waiting');
  assert.equal(cells[127].getAttribute('title'), '10.0.0.127: probed, no answer yet');
  assert.ok(cells.slice(128).every((cell) => cell.dataset.state === 'idle'));
  assert.equal(cells[50].dataset.state, 'host');
  assert.match(text(f.find('.office-summary')[0]), /^128 addresses probed 5 hosts answering/);
  f.dispose();
});

test('cards come only from answered rows and the real VM card links to its host', () => {
  const f = harness(mount, OFFICE);
  const map = discoveryMap();
  f.publish(PORTS, { ...map, rows: [] });
  assert.equal(f.find('.office-host').length, 0);
  assert.equal(text(f.find('.office-found-title')[0]), 'No host has answered yet');
  f.publish(PORTS, map);
  const cards = f.find('.office-host');
  assert.deepEqual(cards.map((card) => card.dataset.addr), ['10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13', '10.0.0.50']);
  for (const card of cards.slice(0, 4)) assert.match(text(card), /^\w+ 10\.0\.0\.1\d Simulated by the world$/);
  const real = cards[4];
  assert.match(text(real), /^server 10\.0\.0\.50 Real Ubuntu VM/);
  assert.equal(real.querySelectorAll('.scan-badge')[0].textContent, 'Real Ubuntu VM');
  const button = real.querySelectorAll('button')[0];
  assert.equal(button.textContent, 'Show office in the workspace');
  button.click();
  assert.equal(f.selection.get().host, 'office');
  // A second identical snapshot adds no cards.
  f.publish(PORTS, map);
  assert.equal(f.find('.office-host').length, 5);
  f.dispose();
});

test('the fifth answer seen live marks the moment on the heading and that card', () => {
  const f = harness(mount, OFFICE);
  const map = discoveryMap();
  const four = { ...map, rows: map.rows.filter((row) => row.host !== '10.0.0.12' || row.state !== 'open') };
  f.publish(PORTS, four);
  assert.equal(text(f.find('.office-found-title')[0]), '4 hosts answered');
  assert.equal(f.moments.length, 0);
  f.publish(PORTS, map);
  const heading = f.find('.office-found-title')[0];
  assert.equal(heading.textContent, 'All five hosts answered');
  const files = f.find('.office-host').find((card) => card.dataset.addr === '10.0.0.12');
  assert.deepEqual(f.moments, [heading, files]);
  f.publish(PORTS, map);
  assert.equal(f.moments.length, 2);
  f.dispose();
});

test('a page opened after discovery marks only the heading', () => {
  const f = harness(mount, OFFICE);
  f.publish(PORTS, discoveryMap());
  assert.deepEqual(f.moments, [f.find('.office-found-title')[0]]);
  f.dispose();
});

test('the story strip shows each step, its exit status and the command in play', () => {
  const f = harness(mount, OFFICE);
  f.publish(OFFICE, story(['waiting', 'waiting', 'waiting']));
  assert.equal(text(f.find('.scan-command')[0]), 'Next sudo nmap -sn -n -oX notes/office-1.xml 10.0.0.0/24');
  f.publish(OFFICE, story(['done', 'running', 'waiting'], [0]));
  const steps = f.find('.scan-step');
  assert.deepEqual(steps.map((step) => step.dataset.state), ['done', 'running', 'waiting']);
  assert.equal(text(steps[0]), '1 Host discovery Done · exit 0');
  assert.equal(text(steps[1]), '2 SYN scan with service detection Running');
  assert.equal(text(f.find('.scan-command')[0]), 'Running sudo nmap -sS -sV');
  f.publish(OFFICE, story(['done', 'failed', 'waiting'], [0, 1]));
  assert.equal(text(f.find('.scan-step')[1]), '2 SYN scan with service detection Failed · exit 1');
  assert.equal(text(f.find('.scan-command')[0]), 'Failed sudo nmap -sS -sV');
  assert.equal(f.find('.scan-story-head')[0].querySelectorAll('h2')[0].textContent, 'Scripted agent');
  f.dispose();
});

test('the scanner shows the address its host status reports', () => {
  const f = harness(mount, OFFICE);
  const card = f.find('.office-scanner')[0];
  assert.match(text(card), /^workstation waiting for its lease/);
  f.publish('/api/state/host-workstation', { state: 'network_up', addresses: ['10.0.9.2'], screen: false, terminal: false });
  assert.match(text(card), /^workstation 10\.0\.9\.2 Scanner/);
  f.dispose();
});

test('names from the world are set as text and limits are shown', () => {
  const f = harness(mount, OFFICE);
  const map = scannedMap();
  map.machines[0].name = '<img src=x onerror=alert(1)>';
  map.untracked = 3;
  map.max_rows = 16384;
  f.publish(PORTS, map, { too_large: true });
  assert.equal(f.find('img').length, 0);
  assert.equal(f.find('.office-host')[0].querySelectorAll('b')[0].textContent, '<img src=x onerror=alert(1)>');
  const note = f.find('.loss-note').find((node) => node.textContent);
  assert.match(note.textContent, /passed its size limit/);
  assert.match(note.textContent, /full at 16,384 rows\. 3 later probes to new ports are not shown/);
  assert.equal(text(f.find('.office-summary')[0]), '256 addresses probed 5 hosts answering 11 open ports');
  f.fail(PORTS, new Error('the stream closed'));
  assert.match(note.textContent, /Could not load the port map: the stream closed/);
  f.dispose();
});

test('dispose releases every subscription and listener', () => {
  const f = harness(mount, OFFICE);
  f.publish(PORTS, discoveryMap());
  assert.equal(f.active(), 3);
  const button = f.find('.office-host')[4].querySelectorAll('button')[0];
  assert.equal(button.listenerCount, 1);
  f.dispose();
  assert.equal(f.active(), 0);
  assert.equal(button.listenerCount, 0);
  assert.equal(f.root.children.length, 0);
});
