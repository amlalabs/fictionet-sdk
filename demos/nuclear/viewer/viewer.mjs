// The viewer owns its state stream and sends the plant's typed commands directly.
const byId = (id) => document.getElementById(id);
let current = null;
let connected = false;
let pending = false;
const controls = [...document.querySelectorAll('button')];
const updateControls = () => controls.forEach((button) => { button.disabled = !connected || pending; });
updateControls();

const readings = [
  ['Plant time', (p) => `${(p.at_ms / 1000).toFixed(1)} s`],
  ['Thermal output', (p) => `${p.truth.reactor.thermal_mw.toFixed(1)} MW`],
  ['Reactor power', (p) => `${p.truth.reactor.neutron_power_percent.toFixed(1)} %`],
  ['Primary pressure', (p) => `${p.truth.primary.pressure_mpa.toFixed(2)} MPa`],
  ['Generator output', (p) => `${p.truth.secondary.generator_mw.toFixed(1)} MW`],
  ['Reactor trip', (p) => p.truth.reactor.trip?.cause ?? 'Not tripped'],
];
for (const [name] of readings) {
  const item = document.createElement('div');
  item.textContent = name;
  item.append(document.createElement('output'));
  byId('readings').append(item);
}
const outputs = [...byId('readings').querySelectorAll('output')];
const events = new EventSource('/state');
events.onmessage = ({ data }) => {
  try {
    const state = JSON.parse(data);
    current = state.plant;
    readings.forEach(([, read], i) => { outputs[i].textContent = read(current); });
    byId('story').textContent = state.story.map((line) => `${line.time} · ${line.text}`).join('\n');
    byId('facts').textContent = state.facts.slice().reverse().map((fact) => `${fact.time} · ${fact.kind} · ${fact.summary}`).join('\n');
    byId('snapshot').textContent = JSON.stringify(current, null, 2);
    connected = true;
    byId('connection').textContent = `Live · plant revision ${current.revision}`;
  } catch (error) {
    connected = false;
    byId('connection').textContent = `Cannot read plant state: ${error.message}`;
  }
  updateControls();
};
events.onerror = () => {
  connected = false;
  byId('connection').textContent = 'Plant connection lost. Reconnecting…';
  updateControls();
};

async function command(channel, value) {
  if (!connected || pending) return;
  pending = true;
  updateControls();
  byId('status').textContent = 'Sending…';
  try {
    const response = await fetch(`/api/command/${channel}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value),
    });
    if (!response.ok) throw new Error(`server returned ${response.status}`);
    const reply = await response.json();
    byId('status').textContent = Object.hasOwn(reply, 'Err')
      ? `Refused: ${JSON.stringify(reply.Err)}` : 'Applied.';
  } catch (error) {
    byId('status').textContent = `No confirmed reply: ${error.message}. Read the state before retrying.`;
  } finally {
    pending = false;
    updateControls();
  }
}
for (const button of document.querySelectorAll('[data-command]')) {
  button.onclick = () => command('plant', button.dataset.command);
}
byId('rods').onsubmit = (event) => { event.preventDefault(); command('plant', { rod_demand: { tenths_percent: Math.round(Number(byId('rod-demand').value) * 10) } }); };
byId('scenario').onsubmit = (event) => { event.preventDefault(); command('scenario', { start: { scenario: byId('scenario-name').value, speed: Number(byId('speed').value) } }); };
byId('pace').onsubmit = (event) => { event.preventDefault(); command('scenario', { speed: { speed: Number(byId('speed').value) } }); };
byId('quiet').onclick = () => command('faults', { change: { inject: 'telemetry_quiet' }, expected_revision: current.revision });
byId('clear-faults').onclick = () => command('faults', { change: 'clear_all', expected_revision: current.revision });
