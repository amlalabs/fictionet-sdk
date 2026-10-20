// Supervisory screens for the three controllers of the unit.
//
// render(root, plant, history) fills five parts of the page from one reply of
// /api/plant: the alarm strip, the mimic, the control column, the trend column
// and the status bar. It makes no network calls. The page loop at the end of
// this file polls /api/plant once a second, keeps the newest replies for the
// trends, and sends controls as POST requests when an operator presses a button.

const PLANT_PATH = '/api/plant';
const CONTROL_PATH = '/api/control/';
const POLL_MS = 1000;
const HISTORY_LIMIT = 120;
const SVG_NS = 'http://www.w3.org/2000/svg';

const STATE_WORDS = { normal: 'Normal', active: 'Active', acknowledged: 'Acknowledged' };
const LINK_IDS = ['rps1', 'rcs1', 'bop1'];

// Equipment boxes of the mimic. Each lists the readings it shows, in order.
const BOXES = [
  { title: 'Pressurizer', x: 40, y: 20, w: 150, h: 112, fields: ['pressurizer_pressure', 'pressurizer_level', 'spray_valve'] },
  { title: 'Reactor core', x: 40, y: 170, w: 150, h: 180, fields: ['neutron_power', 'rod_demand', 'core_exit_temperature'] },
  { title: 'Steam generator A', x: 262, y: 30, w: 170, h: 150, fields: ['hot_leg_a', 'sg_level_a', 'steam_flow_a', 'feed_flow_a', 'feed_valve_a'] },
  { title: 'Steam generator B', x: 262, y: 262, w: 170, h: 150, fields: ['hot_leg_b', 'sg_level_b', 'steam_flow_b', 'feed_flow_b', 'feed_valve_b'] },
  { title: 'Turbine', x: 530, y: 30, w: 170, h: 110, fields: ['turbine_valve_position', 'generator_output'] },
  { title: 'Steam dump', x: 530, y: 170, w: 170, h: 90, fields: ['steam_dump_valve'] },
  { title: 'Condenser', x: 530, y: 300, w: 170, h: 90, fields: ['condenser_pressure'] },
];

// Pipes as [x1, y1, x2, y2]. Hot legs leave the reactor; cold legs return to it.
const PIPES = [
  [105, 132, 105, 170],
  [190, 185, 262, 100],
  [262, 160, 190, 240],
  [190, 330, 262, 410],
  [262, 320, 190, 290],
  [432, 80, 530, 80],
  [432, 290, 500, 290],
  [500, 290, 500, 90],
  [470, 230, 432, 150],
  [470, 300, 432, 300],
];

// Pumps as circles on the pipes. `flag` is the status key of the pump.
const PUMPS = [
  { label: 'Coolant pump A', flag: 'coolant_pump_a', x: 236, y: 189 },
  { label: 'Coolant pump B', flag: 'coolant_pump_b', x: 236, y: 309 },
  { label: 'Feed pump A', flag: 'feed_pump_a', x: 470, y: 230 },
  { label: 'Feed pump B', flag: 'feed_pump_b', x: 470, y: 300 },
];

const FIELD_LABELS = {
  pressurizer_pressure: 'Pressure',
  pressurizer_level: 'Level',
  spray_valve: 'Spray valve',
  neutron_power: 'Power',
  rod_demand: 'Rod demand',
  core_exit_temperature: 'Core exit',
  hot_leg_a: 'Hot leg',
  hot_leg_b: 'Hot leg',
  sg_level_a: 'Level',
  sg_level_b: 'Level',
  steam_flow_a: 'Steam flow',
  steam_flow_b: 'Steam flow',
  feed_flow_a: 'Feed flow',
  feed_flow_b: 'Feed flow',
  feed_valve_a: 'Feed valve',
  feed_valve_b: 'Feed valve',
  turbine_valve_position: 'Turbine valve',
  generator_output: 'Output',
  steam_dump_valve: 'Steam dump valve',
  condenser_pressure: 'Pressure',
};

const TRENDS = [
  { id: 'neutron_power', label: 'Neutron power' },
  { id: 'pressurizer_pressure', label: 'Pressurizer pressure' },
  { id: 'hot_leg_a', label: 'Hot leg A' },
  { id: 'steam_pressure', label: 'Steam pressure' },
  { id: 'pressurizer_level', label: 'Pressurizer level' },
  { id: 'generator_output', label: 'Generator output' },
];

const PUMP_CONTROLS = [
  { name: 'coolant-a', label: 'Coolant pump A', flag: 'coolant_pump_a' },
  { name: 'coolant-b', label: 'Coolant pump B', flag: 'coolant_pump_b' },
  { name: 'feed-a', label: 'Feed pump A', flag: 'feed_pump_a' },
  { name: 'feed-b', label: 'Feed pump B', flag: 'feed_pump_b' },
  { name: 'aux-feed', label: 'Auxiliary feed pump', flag: 'auxiliary_feed' },
  { name: 'circ-water', label: 'Circulating water pump', flag: 'circulating_water' },
];

const VALVE_CONTROLS = [
  { name: 'feed-a', label: 'Feed valve A', reading: 'feed_valve_a' },
  { name: 'feed-b', label: 'Feed valve B', reading: 'feed_valve_b' },
  { name: 'turbine', label: 'Turbine valve', reading: 'turbine_valve_position' },
  { name: 'steam-dump', label: 'Steam dump valve', reading: 'steam_dump_valve' },
  { name: 'spray', label: 'Pressurizer spray valve', reading: 'spray_valve' },
];

const CONTROLLER_CONTROLS = [
  { name: 'pressurizer', label: 'Pressurizer pressure control', mode: 'pressurizer' },
  { name: 'feed-a', label: 'Feed level control A', mode: 'feed_a' },
  { name: 'feed-b', label: 'Feed level control B', mode: 'feed_b' },
  { name: 'steam-dump', label: 'Steam dump control', mode: 'steam_dump' },
];

const parts = new WeakMap();
let pollNow = () => {};

function make(doc, tag, attrs = {}, text) {
  const node = doc.createElement(tag);
  setAttributes(node, attrs);
  if (text !== undefined) node.textContent = text;
  return node;
}

function svg(doc, tag, attrs = {}, text) {
  const node = doc.createElementNS(SVG_NS, tag);
  setAttributes(node, attrs);
  if (text !== undefined) node.textContent = text;
  return node;
}

function setAttributes(node, attrs) {
  for (const [name, value] of Object.entries(attrs)) {
    if (name === 'class') {
      for (const token of String(value).split(' ')) {
        if (token) node.classList.add(token);
      }
    } else {
      node.setAttribute(name, String(value));
    }
  }
}

function formatValue(reading) {
  if (!reading || reading.value === null || reading.value === undefined) return '—';
  const digits = reading.unit === 'MPa' ? 2 : reading.unit === 'pcm' ? 0 : 1;
  return `${reading.value.toFixed(digits)} ${reading.unit}`;
}

function seconds(ms) {
  return `${(ms / 1000).toFixed(1)} s`;
}

function partsFor(root) {
  let found = parts.get(root);
  if (found) return found;
  const doc = root.ownerDocument ?? globalThis.document;
  found = {
    doc,
    annunciators: buildAnnunciators(doc),
    mimic: buildMimic(doc),
    controls: buildControls(doc),
    trends: buildTrends(doc),
    status: buildStatus(doc),
  };
  root.textContent = '';
  root.appendChild(found.annunciators.section);
  root.appendChild(found.mimic.section);
  root.appendChild(found.controls.section);
  root.appendChild(found.trends.section);
  root.appendChild(found.status.bar);
  parts.set(root, found);
  return found;
}

/**
 * Shows the page's connection notice in the status bar. An empty string clears it.
 */
export function showNotice(root, text) {
  partsFor(root).status.notice.textContent = text;
}

/**
 * Fills the five parts of the page from one reply of /api/plant. `history`
 * holds earlier replies, oldest first, for the trends.
 */
export function render(root, plant, history = []) {
  const p = partsFor(root);
  updateAnnunciators(p.annunciators, plant.alarms ?? []);
  updateMimic(p.mimic, plant);
  p.controls.update(plant);
  updateTrends(p.trends, plant, history);
  fillStatus(p.status, plant);
}

// ---- Alarm strip -----------------------------------------------------------

function buildAnnunciators(doc) {
  const section = make(doc, 'section', { class: 'panel annunciators', 'aria-label': 'Alarms' });
  const heading = make(doc, 'h2', { class: 'panel-title' }, 'Alarms');
  const summary = make(doc, 'span', { class: 'alarm-summary' });
  const list = make(doc, 'ul', { class: 'tiles' });
  section.appendChild(heading);
  section.appendChild(summary);
  section.appendChild(list);
  return { doc, section, summary, list, tiles: new Map() };
}

function updateAnnunciators(a, alarms) {
  let active = 0;
  for (const alarm of alarms) {
    let tile = a.tiles.get(alarm.id);
    if (!tile) {
      const item = make(a.doc, 'li', { class: 'tile', 'data-alarm': alarm.id });
      const label = make(a.doc, 'span', { class: 'tile-label' }, alarm.label);
      const state = make(a.doc, 'span', { class: 'tile-state' });
      item.appendChild(label);
      item.appendChild(state);
      a.list.appendChild(item);
      tile = { item, state };
      a.tiles.set(alarm.id, tile);
    }
    for (const word of Object.keys(STATE_WORDS)) tile.item.classList.remove(word);
    tile.item.classList.add(alarm.state);
    tile.state.textContent = STATE_WORDS[alarm.state] ?? alarm.state;
    if (alarm.state === 'active') active += 1;
  }
  a.summary.textContent = `${active} active`;
}

// ---- Mimic -----------------------------------------------------------------

function buildMimic(doc) {
  const section = make(doc, 'section', { class: 'panel mimic', 'aria-label': 'Plant mimic' });
  const picture = svg(doc, 'svg', {
    viewBox: '0 0 720 440',
    role: 'img',
    'aria-label': 'Mimic of the primary and secondary circuits with live readings and pump state',
  });
  for (const [x1, y1, x2, y2] of PIPES) {
    picture.appendChild(svg(doc, 'line', { x1, y1, x2, y2, class: 'pipe' }));
  }
  const readings = new Map();
  for (const box of BOXES) {
    picture.appendChild(svg(doc, 'rect', { x: box.x, y: box.y, width: box.w, height: box.h, rx: 6, class: 'equipment' }));
    picture.appendChild(svg(doc, 'text', { x: box.x + 10, y: box.y + 22, class: 'equipment-title' }, box.title));
    box.fields.forEach((id, i) => {
      const text = svg(doc, 'text', { x: box.x + 10, y: box.y + 46 + i * 18, class: 'reading', 'data-reading': id });
      picture.appendChild(text);
      readings.set(id, { text, label: FIELD_LABELS[id] ?? id });
    });
  }
  const pumps = new Map();
  for (const pump of PUMPS) {
    const circle = svg(doc, 'circle', { cx: pump.x, cy: pump.y, r: 16, class: 'pump', 'data-pump': pump.flag });
    const name = svg(doc, 'text', { x: pump.x, y: pump.y + 34, class: 'pump-name', 'text-anchor': 'middle' }, pump.label);
    const state = svg(doc, 'text', { x: pump.x, y: pump.y + 50, class: 'pump-state', 'text-anchor': 'middle' });
    picture.appendChild(circle);
    picture.appendChild(name);
    picture.appendChild(state);
    pumps.set(pump.flag, { circle, state });
  }
  section.appendChild(picture);
  return { section, readings, pumps };
}

function updateMimic(m, plant) {
  for (const [id, entry] of m.readings) {
    const reading = plant.readings?.[id];
    entry.text.textContent = `${entry.label}: ${formatValue(reading)}`;
    setFlag(entry.text, 'stale', reading?.stale === true);
  }
  for (const [flag, pump] of m.pumps) {
    const running = plant.status?.[flag];
    pump.circle.classList.remove('running', 'stopped', 'unknown');
    pump.circle.classList.add(running === true ? 'running' : running === false ? 'stopped' : 'unknown');
    pump.state.textContent = running === true ? 'Running' : running === false ? 'Stopped' : 'No data';
  }
}

function setFlag(node, name, on) {
  if (on) node.classList.add(name);
  else node.classList.remove(name);
}

// ---- Controls --------------------------------------------------------------

function buildControls(doc) {
  const section = make(doc, 'section', { class: 'panel controls', 'aria-label': 'Controls' });
  section.appendChild(make(doc, 'h2', { class: 'panel-title' }, 'Controls'));
  const message = make(doc, 'p', { class: 'message', role: 'status' }, 'Ready.');

  const reactor = group(doc, 'Reactor');
  reactor.add(button(doc, 'Trip reactor', 'danger', () => post('trip', {}, 'Trip reactor', message)));
  reactor.add(button(doc, 'Reset trip', '', () => post('reset', {}, 'Reset trip', message)));
  reactor.add(button(doc, 'Acknowledge alarms', '', () => post('acknowledge', {}, 'Acknowledge alarms', message)));
  section.appendChild(reactor.node);

  const rodGroup = group(doc, 'Rods');
  const rod = numberRow({
    doc,
    label: 'Demand (%)',
    inputLabel: 'Rod demand (%)',
    buttonText: 'Set',
    buttonLabel: 'Set rod demand',
    message,
    onValue: (percent) => post('rod-demand', { percent }, 'Rod demand', message),
  });
  rodGroup.add(rod.node);
  section.appendChild(rodGroup.node);

  const pumpGroup = group(doc, 'Pumps');
  const pumps = PUMP_CONTROLS.map((pump) => {
    const state = make(doc, 'span', { class: 'row-state' });
    const toggle = { next: true };
    const btn = button(
      doc,
      'Start',
      '',
      () => post('pump', { name: pump.name, running: toggle.next }, `${toggle.next ? 'Start' : 'Stop'} ${pump.label.toLowerCase()}`, message),
      `Start ${pump.label}`,
    );
    pumpGroup.add(row(doc, pump.label, state, btn));
    return { label: pump.label, flag: pump.flag, state, btn, toggle };
  });
  section.appendChild(pumpGroup.node);

  const valveGroup = group(doc, 'Valve demands');
  const valves = VALVE_CONTROLS.map((valve) => {
    const field = numberRow({
      doc,
      label: valve.label,
      inputLabel: `${valve.label} demand (%)`,
      buttonText: 'Set',
      buttonLabel: `Set ${valve.label}`,
      message,
      onValue: (percent) => post('valve', { name: valve.name, percent }, valve.label, message),
    });
    valveGroup.add(field.node);
    return { reading: valve.reading, input: field.input };
  });
  section.appendChild(valveGroup.node);

  const controllerGroup = group(doc, 'Controllers');
  const controllers = CONTROLLER_CONTROLS.map((controller) => {
    const state = make(doc, 'span', { class: 'row-state' });
    const toggle = { auto: false };
    const btn = button(
      doc,
      'Set manual',
      '',
      () => post('controller', { name: controller.name, auto: toggle.auto }, `${controller.label}: ${toggle.auto ? 'automatic' : 'manual'}`, message),
      `Set ${controller.label} to manual`,
    );
    controllerGroup.add(row(doc, controller.label, state, btn));
    return { label: controller.label, mode: controller.mode, state, btn, toggle };
  });
  section.appendChild(controllerGroup.node);

  const heaterGroup = group(doc, 'Heaters');
  const heaterState = make(doc, 'span', { class: 'row-state' });
  const heaterToggle = { on: true };
  const heaterButton = button(doc, 'Turn heaters on', '', () =>
    post('heaters', { on: heaterToggle.on }, `Heaters ${heaterToggle.on ? 'on' : 'off'}`, message),
  );
  heaterGroup.add(row(doc, 'Pressurizer heaters', heaterState, heaterButton));
  section.appendChild(heaterGroup.node);

  section.appendChild(message);

  return {
    section,
    update(plant) {
      for (const pump of pumps) {
        const running = plant.status?.[pump.flag];
        const verb = running === true ? 'Stop' : 'Start';
        pump.state.textContent = running === true ? 'Running' : running === false ? 'Stopped' : 'No data';
        pump.btn.textContent = verb;
        pump.btn.setAttribute('aria-label', `${verb} ${pump.label}`);
        pump.toggle.next = running !== true;
      }
      for (const controller of controllers) {
        const mode = plant.modes?.[controller.mode];
        const next = mode === 'automatic' ? 'manual' : 'automatic';
        controller.state.textContent = mode === 'automatic' ? 'Automatic' : mode === 'manual' ? 'Manual' : 'No data';
        controller.btn.textContent = `Set ${next}`;
        controller.btn.setAttribute('aria-label', `Set ${controller.label} to ${next}`);
        controller.toggle.auto = mode !== 'automatic';
      }
      const heaters = plant.status?.heaters;
      heaterState.textContent = heaters === true ? 'On' : heaters === false ? 'Off' : 'No data';
      heaterButton.textContent = heaters === true ? 'Turn heaters off' : 'Turn heaters on';
      heaterToggle.on = heaters !== true;
      rod.input.setAttribute('placeholder', formatValue(plant.readings?.rod_demand));
      for (const valve of valves) {
        const reading = plant.readings?.[valve.reading];
        valve.input.setAttribute('placeholder', formatValue(reading));
      }
    },
  };
}

function group(doc, title) {
  const node = make(doc, 'div', { class: 'control-group' });
  node.appendChild(make(doc, 'h3', { class: 'group-title' }, title));
  return {
    node,
    add(child) {
      node.appendChild(child);
    },
  };
}

function row(doc, label, control, action) {
  const item = make(doc, 'div', { class: 'control-row' });
  item.appendChild(make(doc, 'span', { class: 'row-label' }, label));
  item.appendChild(control);
  item.appendChild(action);
  return item;
}

function button(doc, text, kind, onPress, ariaLabel = text) {
  const node = make(doc, 'button', { type: 'button', class: `control-button ${kind}`.trim(), 'aria-label': ariaLabel }, text);
  node.addEventListener('click', onPress);
  return node;
}

/**
 * A row with a percent field and a button. An empty or non-numeric field
 * asks for a percent on the message line and sends nothing.
 */
function numberRow({ doc, label, inputLabel, buttonText, buttonLabel, message, onValue }) {
  const input = numberInput(doc, inputLabel);
  const set = button(doc, buttonText, '', () => {
    const value = Number(input.value);
    if (input.value === '' || !Number.isFinite(value)) {
      message.textContent = `${inputLabel}: enter a percent from 0 to 100`;
      return undefined;
    }
    return onValue(value);
  }, buttonLabel);
  return { node: row(doc, label, input, set), input };
}

function numberInput(doc, label) {
  return make(doc, 'input', {
    type: 'number',
    min: 0,
    max: 100,
    step: 0.1,
    class: 'control-input',
    'aria-label': label,
  });
}

/**
 * Sends one control and shows the answer in the control panel's message line.
 * Then it asks for a fresh reply so the screen shows the change at once.
 */
async function post(path, body, label, message) {
  message.textContent = `${label}: sending`;
  const reply = await send(path, body);
  message.textContent = reply.ok ? `${label}: done` : `${label} refused: ${reply.reason}`;
  pollNow();
}

async function send(path, body) {
  try {
    const response = await fetch(CONTROL_PATH + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    let reply = {};
    try {
      reply = await response.json();
    } catch {
      // The reply had no JSON body, so the status alone says what happened.
    }
    return {
      ok: response.ok && reply.ok !== false,
      reason: reply.reason ?? `status ${response.status}`,
    };
  } catch {
    return { ok: false, reason: 'no answer from the HMI' };
  }
}

// ---- Trends ----------------------------------------------------------------

function buildTrends(doc) {
  const section = make(doc, 'section', { class: 'panel trends', 'aria-label': 'Trends' });
  section.appendChild(make(doc, 'h2', { class: 'panel-title' }, 'Trends'));
  const rows = TRENDS.map((trend) => {
    const item = make(doc, 'div', { class: 'trend' });
    const label = make(doc, 'span', { class: 'trend-label' }, trend.label);
    const value = make(doc, 'span', { class: 'trend-value' });
    const picture = svg(doc, 'svg', { viewBox: '0 0 160 40', class: 'sparkline', role: 'img', 'aria-label': `${trend.label} history` });
    const line = svg(doc, 'polyline', { class: 'trend-line', points: '' });
    picture.appendChild(line);
    item.appendChild(label);
    item.appendChild(value);
    item.appendChild(picture);
    section.appendChild(item);
    return { id: trend.id, value, line };
  });
  return { section, rows };
}

function sparkPoints(values) {
  if (values.length < 2) return '';
  const low = Math.min(...values);
  const high = Math.max(...values);
  const span = high - low || 1;
  const step = 160 / (values.length - 1);
  return values
    .map((value, i) => `${(i * step).toFixed(1)},${(36 - ((value - low) / span) * 32 + 2).toFixed(1)}`)
    .join(' ');
}

function updateTrends(t, plant, history) {
  for (const row of t.rows) {
    row.value.textContent = formatValue(plant.readings?.[row.id]);
    const values = history
      .map((sample) => sample.readings?.[row.id]?.value)
      .filter((value) => typeof value === 'number');
    row.line.setAttribute('points', sparkPoints(values));
  }
}

// ---- Status bar ------------------------------------------------------------

function buildStatus(doc) {
  const bar = make(doc, 'footer', { class: 'panel statusbar' });
  const clock = make(doc, 'span', { class: 'status-item clock' });
  const links = new Map();
  bar.appendChild(clock);
  for (const id of LINK_IDS) {
    const link = make(doc, 'span', { class: 'status-item link' });
    bar.appendChild(link);
    links.set(id, link);
  }
  const notice = make(doc, 'span', { class: 'status-item notice', role: 'status' });
  bar.appendChild(notice);
  return { bar, clock, links, notice };
}

function fillStatus(s, plant) {
  s.clock.textContent = plant.clock_ms === null || plant.clock_ms === undefined
    ? 'Clock: waiting for the first poll'
    : `Clock ${seconds(plant.clock_ms)}`;
  for (const link of plant.links ?? []) {
    const item = s.links.get(link.id);
    if (!item) continue;
    const last = link.read_ms === null || link.read_ms === undefined ? 'never read' : `last poll ${seconds(link.read_ms)}`;
    const heartbeat = link.heartbeat == null ? 'not yet read' : link.heartbeat;
    item.textContent = `${link.id} ${link.online ? 'online' : 'offline'}, ${last}, heartbeat ${heartbeat}`;
    setFlag(item, 'offline', !link.online);
  }
}

// ---- Page loop -------------------------------------------------------------

/**
 * Polls /api/plant every POLL_MS, renders each reply and keeps the newest
 * HISTORY_LIMIT replies for the trends.
 */
export function start(root, interval = POLL_MS) {
  const history = [];
  let busy = false;
  const tick = async () => {
    if (busy) return;
    busy = true;
    try {
      const response = await fetch(PLANT_PATH, { cache: 'no-store' });
      if (!response.ok) throw new Error(`status ${response.status}`);
      const plant = await response.json();
      history.push(plant);
      if (history.length > HISTORY_LIMIT) history.splice(0, history.length - HISTORY_LIMIT);
      render(root, plant, history);
      showNotice(root, '');
    } catch {
      showNotice(root, 'No data from the HMI. Retrying.');
    } finally {
      busy = false;
    }
  };
  pollNow = tick;
  tick();
  return setInterval(tick, interval);
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const root = document.getElementById('hmi');
  if (root) start(root);
}
