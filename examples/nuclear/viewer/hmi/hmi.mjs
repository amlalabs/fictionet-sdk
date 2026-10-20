// Supervisory screens for the three controllers of the unit.
//
// render(root, plant, history) fills five parts of the page from one reply of
// /api/plant: the alarm strip, the mimic, the control column, the trend column
// and the status bar. It makes no network calls. The page loop at the end of
// this file polls /api/plant and /api/trend once a second and sends controls
// as POST requests when an operator presses a button.

const PLANT_PATH = '/api/plant';
const CONTROL_PATH = '/api/control/';
const POLL_MS = 1000;

const SVG_NS = 'http://www.w3.org/2000/svg';

const STATE_WORDS = { normal: 'Normal', active: 'Active', acknowledged: 'Acknowledged' };
const LINK_IDS = ['rps1', 'rcs1', 'bop1'];

// Equipment boxes of the mimic. Each lists the readings it shows, in order.
const BOXES = [
  { title: 'Reactor core', x: 20, y: 20, w: 340, h: 245, fields: ['neutron_power', 'rod_position', 'shutdown_rods', 'rod_demand', 'core_exit_temperature'], flags: ['reactor_tripped'] },
  { title: 'Pressurizer', x: 20, y: 320, w: 340, h: 220, fields: ['pressurizer_pressure', 'pressurizer_level', 'spray_valve'], flags: ['heaters', 'pressurizer_relief'] },
  { title: 'Loop A · Steam generator A', x: 400, y: 20, w: 340, h: 390, fields: ['hot_leg_a', 'cold_leg_a', 'coolant_flow_a', 'sg_level_a', 'steam_flow_a', 'feed_flow_a', 'feed_valve_a'], flags: ['coolant_pump_a', 'feed_pump_a'] },
  { title: 'Loop B · Steam generator B', x: 400, y: 460, w: 340, h: 390, fields: ['hot_leg_b', 'cold_leg_b', 'coolant_flow_b', 'sg_level_b', 'steam_flow_b', 'feed_flow_b', 'feed_valve_b'], flags: ['coolant_pump_b', 'feed_pump_b'] },
  { title: 'Turbine / Generator', x: 780, y: 20, w: 340, h: 220, fields: ['turbine_valve', 'turbine_valve_position', 'generator_output'], flags: ['turbine_tripped'] },
  { title: 'Steam header', x: 780, y: 300, w: 340, h: 175, fields: ['steam_pressure', 'steam_dump_valve'], flags: ['steam_relief'] },
  { title: 'Condenser / Feedwater', x: 780, y: 550, w: 340, h: 200, fields: ['condenser_pressure'], flags: ['circulating_water', 'auxiliary_feed'] },
];

// Connections end at equipment edges. Text stays inside the equipment.
const PIPES = [
  [180, 265, 180, 320],
  [360, 90, 400, 90], [360, 220, 400, 220],
  [360, 150, 380, 150], [380, 150, 380, 670], [380, 670, 400, 670],
  [360, 240, 370, 240], [370, 240, 370, 800], [370, 800, 400, 800],
  [740, 100, 780, 100], [740, 520, 760, 520], [760, 520, 760, 140], [760, 140, 780, 140],
  [950, 240, 950, 300], [950, 475, 950, 550],
  [780, 650, 740, 650], [780, 610, 750, 610], [750, 610, 750, 370], [750, 370, 740, 370],
];

const FLAGS = {
  reactor_tripped: ['Reactor trip', 'Tripped', 'Clear', true, 'rps1'],
  turbine_tripped: ['Turbine trip', 'Tripped', 'Clear', true, 'bop1'],
  heaters: ['Pressurizer heaters', 'On', 'Off', null, 'rcs1'],
  pressurizer_relief: ['Pressurizer relief', 'Open', 'Closed', true, 'rcs1'],
  steam_relief: ['Steam relief', 'Open', 'Closed', true, 'bop1'],
  coolant_pump_a: ['Coolant pump A', 'Running', 'Stopped', false, 'rcs1'],
  coolant_pump_b: ['Coolant pump B', 'Running', 'Stopped', false, 'rcs1'],
  feed_pump_a: ['Feed pump A', 'Running', 'Stopped', false, 'bop1'],
  feed_pump_b: ['Feed pump B', 'Running', 'Stopped', false, 'bop1'],
  auxiliary_feed: ['Auxiliary feed', 'Running', 'Stopped', false, 'bop1'],
  circulating_water: ['Circulating water', 'Running', 'Stopped', false, 'bop1'],
};

const FIELD_LABELS = {
  rod_position: 'Rod position',
  shutdown_rods: 'Shutdown rods',
  cold_leg_a: 'Cold leg',
  cold_leg_b: 'Cold leg',
  coolant_flow_a: 'Coolant flow',
  coolant_flow_b: 'Coolant flow',
  steam_pressure: 'Steam pressure',
  turbine_valve: 'Valve position',
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
  turbine_valve_position: 'Valve demand',
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
    clock: make(doc, 'time', { class: 'site-clock' }),
    annunciators: buildAnnunciators(doc),
    mimic: buildMimic(doc),
    controls: buildControls(doc),
    trends: buildTrends(doc),
    status: buildStatus(doc),
  };
  root.textContent = '';
  const header = make(doc, 'header', { class: 'top' });
  header.appendChild(make(doc, 'h1', {}, 'ASHCOMBE UNIT 1 · PLANT OVERVIEW'));
  header.appendChild(found.clock);
  root.appendChild(header);
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
 * accepts server histories by point, or earlier plant replies, oldest first.
 */
export function render(root, plant, history = []) {
  const p = partsFor(root);
  p.clock.textContent = plant.plant_time ?? 'Site time: awaiting first poll';
  p.clock.setAttribute('datetime', plant.plant_time ?? '');
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
  const entries = make(doc, 'ul', { class: 'alarm-entries', 'aria-label': 'Alarm time in' });
  section.appendChild(entries);
  return { doc, section, summary, list, entries, tiles: new Map() };
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
  a.entries.textContent = '';
  const current = alarms.filter((alarm) => alarm.state === 'active' || alarm.state === 'acknowledged');
  for (const alarm of current) {
    const time = alarm.in_ms == null ? 'Time unavailable' : `${Math.floor(alarm.in_ms / 60000)}:${((alarm.in_ms % 60000) / 1000).toFixed(1).padStart(4, '0')}`;
    a.entries.appendChild(make(a.doc, 'li', {}, `${time} · ${alarm.label} · ${STATE_WORDS[alarm.state]}`));
  }
  if (!current.length) a.entries.appendChild(make(a.doc, 'li', {}, 'No active alarms.'));
}

// ---- Mimic -----------------------------------------------------------------

function buildMimic(doc) {
  const section = make(doc, 'section', { class: 'panel mimic', 'aria-label': 'Plant mimic' });
  const picture = svg(doc, 'svg', {
    viewBox: '0 0 1140 870',
    role: 'img',
    'aria-label': 'Mimic of the primary and secondary circuits with live readings and pump state',
  });
  for (const [x1, y1, x2, y2] of PIPES) {
    picture.appendChild(svg(doc, 'line', { x1, y1, x2, y2, class: 'pipe' }));
  }
  const readings = new Map();
  const pumps = new Map();
  for (const box of BOXES) {
    picture.appendChild(svg(doc, 'rect', { x: box.x, y: box.y, width: box.w, height: box.h, rx: 6, class: 'equipment' }));
    picture.appendChild(svg(doc, 'text', { x: box.x + 10, y: box.y + 22, class: 'equipment-title' }, box.title));
    box.fields.forEach((id, i) => {
      const text = svg(doc, 'text', { x: box.x + 10, y: box.y + 54 + i * 30, class: 'reading', 'data-reading': id });
      picture.appendChild(text);
      readings.set(id, { text, label: FIELD_LABELS[id] ?? id });
    });
    box.flags.forEach((flag, i) => {
      const y = box.y + 54 + (box.fields.length + i) * 30;
      const [label] = FLAGS[flag];
      const circle = svg(doc, 'circle', { cx: box.x + 17, cy: y - 5, r: 6, class: 'pump', 'data-pump': flag });
      const name = svg(doc, 'text', { x: box.x + 32, y, class: 'pump-name' }, label);
      const state = svg(doc, 'text', { x: box.x + 250, y, class: 'pump-state', 'data-status': flag });
      picture.appendChild(circle);
      picture.appendChild(name);
      picture.appendChild(state);
      pumps.set(flag, { circle, state });
    });
  }
  section.appendChild(picture);
  return { section, readings, pumps };
}

function updateMimic(m, plant) {
  for (const [id, entry] of m.readings) {
    const reading = plant.readings?.[id];
    entry.text.textContent = `${reading?.tag ?? "—"} ${entry.label}: ${formatValue(reading)}`;
    setFlag(entry.text, 'stale', reading?.stale === true);
  }
  for (const [flag, pump] of m.pumps) {
    const running = plant.status?.[flag];
    pump.circle.classList.remove('running', 'stopped', 'unknown');
    pump.circle.classList.add(running === true ? 'running' : running === false ? 'stopped' : 'unknown');
    const [, on, off, abnormal, controller] = FLAGS[flag];
    const stale = plant.links?.some((link) => link.id === controller && !link.online);
    pump.state.textContent = stale ? 'Stale' : running === true ? on : running === false ? off : 'No data';
    setFlag(pump.state, 'abnormal', running != null && running === abnormal);
    setFlag(pump.circle, 'abnormal', running != null && running === abnormal);
    setFlag(pump.state, 'stale', stale || running == null);
    setFlag(pump.circle, 'stale', stale || running == null);
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
  let armedUntil = 0;
  let armTimer;
  const note = make(doc, 'p', { id: 'trip-note', role: 'status', class: 'trip-note' });
  const resetArm = () => {
    armedUntil = 0;
    clearTimeout(armTimer);
    trip.textContent = 'Trip reactor';
    trip.setAttribute('aria-label', 'Trip reactor');
    trip.classList.remove('armed');
    note.textContent = '';
  };
  const trip = button(doc, 'Trip reactor', '', () => {
    if (armedUntil > Date.now()) {
      resetArm();
      return post('trip', {}, 'Trip reactor', message);
    }
    resetArm();
    armedUntil = Date.now() + 5000;
    trip.textContent = 'Confirm trip';
    trip.setAttribute('aria-label', 'Confirm trip');
    trip.classList.add('armed');
    note.textContent = 'Trip armed for 5 seconds. Press Confirm trip to trip the reactor.';
    armTimer = setTimeout(resetArm, 5000);
    return undefined;
  });
  trip.setAttribute('aria-describedby', 'trip-note');
  reactor.add(trip);
  reactor.add(note);
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
    const gaps = svg(doc, 'path', { class: 'trend-line', d: '' });
    picture.appendChild(line);
    picture.appendChild(gaps);
    item.appendChild(label);
    item.appendChild(value);
    item.appendChild(picture);
    section.appendChild(item);
    return { id: trend.id, value, line, gaps };
  });
  return { section, rows };
}

function sparkSegments(samples) {
  const values = samples.map((sample) => sample.value).filter((value) => typeof value === 'number');
  if (values.length < 2) return [];
  const low = Math.min(...values);
  const span = Math.max(...values) - low || 1;
  const start = samples[0].clock_ms;
  const duration = samples.at(-1).clock_ms - start;
  const segments = [];
  let segment = [];
  for (const [i, sample] of samples.entries()) {
    if (typeof sample.value !== 'number') {
      if (segment.length > 1) segments.push(segment);
      segment = [];
      continue;
    }
    const x = duration > 0 ? (sample.clock_ms - start) / duration * 160 : i / (samples.length - 1) * 160;
    segment.push(`${x.toFixed(1)},${(38 - (sample.value - low) / span * 32).toFixed(1)}`);
  }
  if (segment.length > 1) segments.push(segment);
  return segments;
}

function updateTrends(t, plant, history) {
  for (const row of t.rows) {
    row.value.textContent = formatValue(plant.readings?.[row.id]);
    const samples = Array.isArray(history)
      ? history.map((sample) => ({ clock_ms: sample.clock_ms, value: sample.readings?.[row.id]?.value }))
      : history[row.id]?.samples ?? [];
    const segments = sparkSegments(samples);
    row.line.setAttribute('points', segments[0]?.join(' ') ?? '');
    row.gaps.setAttribute('d', segments.slice(1).map((segment) => `M${segment.join(' L')}`).join(' '));
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
    : `Elapsed ${seconds(plant.clock_ms)}`;
  for (const link of plant.links ?? []) {
    const item = s.links.get(link.id);
    if (!item) continue;
    const last = link.read_ms === null || link.read_ms === undefined ? 'never read' : `last poll ${seconds(link.read_ms)}`;
    const heartbeat = link.heartbeat == null ? 'not yet read' : link.heartbeat;
    item.textContent = `${link.id} ${link.online ? 'COMM OK' : `COMM FAIL: ${link.error ?? 'awaiting first poll'}`}, ${last}, heartbeat ${heartbeat}`;
    setFlag(item, 'offline', !link.online);
  }
}

// ---- Page loop -------------------------------------------------------------

/**
 * Polls the held plant values and the server history every POLL_MS.
 */
export function start(root, interval = POLL_MS) {

  let busy = false;
  const tick = async () => {
    if (busy) return;
    busy = true;
    let plantReceived = false;
    try {
      const response = await fetch(PLANT_PATH, { cache: 'no-store' });
      if (!response.ok) throw new Error(`status ${response.status}`);
      const plant = await response.json();
      render(root, plant);
      plantReceived = true;
      const histories = await Promise.all(TRENDS.map(async ({ id }) => {
        const reply = await fetch(`/api/trend?point=${id}&minutes=10`, { cache: 'no-store' });
        if (!reply.ok) throw new Error('History unavailable');
        return [id, await reply.json()];
      }));
      render(root, plant, Object.fromEntries(histories));
      showNotice(root, '');
    } catch {
      showNotice(root, plantReceived ? 'Trend history unavailable. Retrying.' : 'No data from the HMI. Retrying.');
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
