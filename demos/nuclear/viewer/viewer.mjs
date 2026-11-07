import { mount } from './control-room.mjs';

const byId = (id) => document.getElementById(id);
let current = null;
let connected = false;
let pending = false;

function updateControls() {
  for (const control of document.querySelectorAll('#scenario button, #pace button, #quiet, #clear-faults')) {
    control.disabled = !connected || pending;
  }
}

async function post(path, command, signal) {
  const response = await fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(command), signal,
  });
  if (!response.ok) throw new Error(`server returned ${response.status}`);
  return response.json();
}

const events = new EventSource('/state');
events.onmessage = ({ data }) => {
  try {
    const state = JSON.parse(data);
    current = state.plant;
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
    const reply = await post(`/api/command/${channel}`, value);
    byId('status').textContent = Object.hasOwn(reply, 'Err')
      ? `Refused: ${JSON.stringify(reply.Err)}` : 'Applied.';
  } catch (error) {
    byId('status').textContent = `No confirmed reply: ${error.message}. Read the state before retrying.`;
  } finally {
    pending = false;
    updateControls();
  }
}
byId('scenario').onsubmit = (event) => { event.preventDefault(); command('scenario', { start: { scenario: byId('scenario-name').value, speed: Number(byId('speed').value) } }); };
byId('pace').onsubmit = (event) => { event.preventDefault(); command('scenario', { speed: { speed: Number(byId('speed').value) } }); };
byId('quiet').onclick = () => command('faults', { change: { inject: 'telemetry_quiet' }, expected_revision: current.revision });
byId('clear-faults').onclick = () => command('faults', { change: 'clear_all', expected_revision: current.revision });

const dispose = mount(byId('control-room'), {
  state(receive, failed) {
    const onState = ({ data }) => {
      try { receive(JSON.parse(data).plant); } catch (error) { failed(error); }
    };
    const onError = () => failed(new Error('Plant connection lost. Reconnecting…'));
    events.addEventListener('message', onState);
    events.addEventListener('error', onError);
    return () => {
      events.removeEventListener('message', onState);
      events.removeEventListener('error', onError);
    };
  },
  transport: { post },
}, { command: '/api/command/plant', faults: '/api/command/faults' });
updateControls();
window.addEventListener('pagehide', () => { dispose(); events.close(); }, { once: true });
