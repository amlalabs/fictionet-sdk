// Concrete app projections streamed independently; console transport comes from the kit.
import { badges } from './packages.mjs';
import { incidentRows } from './doors.mjs';
import { nameDiff } from './common.mjs';
const token = new URLSearchParams(location.hash.slice(1)).get('token');
const el = (id) => document.getElementById(id);
const streams = [];
let colleaguePath = null;
let packages = null, colleagueInventory = null, requests = [], story = [], scenario = null;
function refreshPackages() {
  if (!packages) return;
  inventory('packages', packages);
  if (colleagueInventory) inventory('colleague', colleagueInventory);
  const incident = incidentRows(requests, packages);
  el('incident').textContent = `${incident.route} upstream attempts · ${incident.messages} simulated peer messages · ${incident.replies} reply folders created · ${incident.refused} folder writes refused`;
}
function stream(path, receive) {
  const events = new EventSource(`${path}/state?token=${encodeURIComponent(token ?? '')}`);
  events.onmessage = ({ data }) => {
    try { receive(JSON.parse(data)); el('connection').textContent = 'Live world observations'; }
    catch (error) { el('connection').textContent = `Cannot read observations: ${error.message}`; }
  };
  events.onerror = () => { el('connection').textContent = 'Connection interrupted. Reconnecting…'; };
  streams.push(events);
}
function text(parent, tag, value) { const node = document.createElement(tag); node.textContent = value ?? '—'; parent.append(node); return node; }
function details(parent, value) { const node = document.createElement('details'); text(node, 'summary', 'Inspect'); text(node, 'pre', JSON.stringify(value, null, 2)); parent.append(node); }
function rows(id, values, columns) {
  const fragment = document.createDocumentFragment();
  for (const value of values) { const tr = document.createElement('tr'); for (const column of columns) { const td = document.createElement('td'); const cell = column(value); if (typeof cell === 'object') details(td, cell); else td.textContent = cell ?? '—'; tr.append(td); } fragment.append(tr); }
  el(id).replaceChildren(fragment);
}
function inventory(id, value) {
  const fragment = document.createDocumentFragment();
  for (const repo of value.repositories) {
    const section = document.createElement('div');
    text(section, 'h3', `${repo.key} · ${repo.kind}`);
    if (repo.upstream) text(section, 'p', `Configured upstream: ${repo.upstream}`);
    const host = scenario?.sessions?.mode === 'separate' ? scenario.sessions.hosts[id === 'colleague' ? 1 : 0] : null;
    const seen = badges(repo.key, host ? requests.filter((tag) => tag.row.sandbox === host) : requests, host ? story.filter((step) => step.host === host) : story);
    for (const pkg of repo.packages) {
      const item = text(section, 'p', ''); item.className = pkg.role;
      if (pkg.role === 'lookalike' && scenario) {
        const diff = nameDiff(pkg.name, scenario.genuine);
        item.append(diff.prefix); text(item, 'mark', diff.a || '∅'); item.append(diff.suffix, ` (genuine: ${scenario.genuine})`);
      } else item.append(pkg.name);
      const badge = seen.get(pkg.name);
      item.append(` · ${pkg.role} · ${pkg.releases.map((release) => release.version).join(', ')}${badge ? ' · downloaded' : ''}${badge?.installed.size ? ' · installed' : ''}`);
      details(section, pkg);
    }
    for (const entry of repo.entries) text(section, 'p', `${entry.path} · ${entry.kind} · ${entry.origin}`);
    fragment.append(section);
  }
  el(id).replaceChildren(fragment);
}
stream('/api/packages', (value) => { packages = value; refreshPackages(); });
stream('/api/doors', (value) => {
  scenario = value.scenario; story = value.story; refreshPackages();
  el('scenario').textContent = `${scenario.variant}: ${scenario.contents} ${scenario.replay ? 'Replay without VMs; commands have no guest exit status.' : 'Scripted workstation session.'} ${scenario.sessions?.description ?? ''}`;
  if (scenario.sessions?.colleague_state && !colleaguePath) { colleaguePath = scenario.sessions.colleague_state; stream(colleaguePath, (value) => { colleagueInventory = value; refreshPackages(); }); }
  rows('story', value.story, [(s) => s.title, (s) => s.host, (s) => s.state, (s) => s.exit, (s) => s.command]);
  el('door-count').textContent = `${value.rows.length} retained · ${value.dropped} dropped · ${value.lost} lost · ${value.setup} setup attempts`;
  rows('doors', value.rows.slice().reverse(), [(r) => r.at.toFixed(2), (r) => r.step, (r) => r.row.name ?? r.row.addr, (r) => r.row.transport, (r) => r.row.outcome, (r) => r.row]);
});
stream('/api/requests', (value) => {
  requests = value.rows; refreshPackages();
  el('request-count').textContent = `${value.rows.length} retained · ${value.dropped} dropped · ${value.lost} lost`;
  rows('requests', value.rows.slice().reverse(), [(r) => r.at.toFixed(2), (r) => r.step, (r) => r.row.method, (r) => `${r.row.host ?? ''}${r.row.path}`, (r) => r.row.classification, (r) => r.row.outcome?.status, (r) => r.row]);
});
try {
  const response = await fetch('/api/hosts', { headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) throw new Error(`server returned ${response.status}`);
  for (const name of await response.json()) { const option = text(el('host'), 'option', name); option.value = name; }
} catch (error) { el('console-status').textContent = `Cannot read hosts: ${error.message}`; }
let dispose = null, socket = null, generation = 0;
function disconnect() { generation++; dispose?.(); dispose = null; socket?.close(); socket = null; el('console').replaceChildren(); el('console-status').textContent = 'Disconnected.'; }
async function open(kind) {
  disconnect(); const attempt = generation;
  try {
    const path = `/console/${encodeURIComponent(el('host').value)}/${kind}?token=${encodeURIComponent(token ?? '')}`;
    let mount;
    if (kind === 'screen') {
      const [{ default: RFB }, component] = await Promise.all([import('/vendor/novnc/core/rfb.js'), import('/screen.mjs')]);
      mount = (socket) => component.mount(el('console'), RFB, socket, { viewOnly: false });
    } else {
      const [library, component] = await Promise.all([import('/vendor/ghostty-web/dist/ghostty-web.js'), import('/terminal.mjs')]);
      const ghostty = await library.Ghostty.load('/vendor/ghostty-web/dist/ghostty-vt.wasm');
      mount = (socket) => component.mount(el('console'), library, socket, { ghostty });
    }
    if (generation !== attempt) return;
    socket = new WebSocket(`ws://${location.host}${path}`);
    dispose = mount(socket);
    el('console-status').textContent = `Connecting ${kind}…`;
    socket.addEventListener('open', () => { if (generation === attempt) el('console-status').textContent = `${kind} connected`; });
    socket.addEventListener('close', () => { if (generation === attempt) el('console-status').textContent = 'Console disconnected. Choose a console to reconnect.'; });
  } catch (error) { if (generation === attempt) el('console-status').textContent = `Console unavailable: ${error.message}`; }
}
el('screen').onclick = () => open('screen'); el('terminal').onclick = () => open('terminal'); el('disconnect').onclick = disconnect;
