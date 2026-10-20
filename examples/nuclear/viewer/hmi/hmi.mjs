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
  auxiliary_feed: ['Auxiliary feed', 'Running', 'Stopped', true, 'bop1'],
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
  { id: 'neutron_power', rangeSpan: 120, label: 'Neutron power' },
  { id: 'pressurizer_pressure', rangeSpan: 6, label: 'Pressurizer pressure' },
  { id: 'hot_leg_a', rangeSpan: 70, label: 'Hot leg A' },
  { id: 'steam_pressure', rangeSpan: 10, label: 'Steam pressure' },
  { id: 'pressurizer_level', rangeSpan: 100, label: 'Pressurizer level' },
  { id: 'generator_output', rangeSpan: 700, label: 'Generator output' },
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
const pollNow = new WeakMap();

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

function siteTime(timestamp, zone) {
  return timestamp ? `${timestamp.slice(11, 19)} ${zone}` : 'Time unavailable';
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
  p.clock.textContent = plant.plant_time ? siteTime(plant.plant_time, plant.zone) : 'Site time: awaiting first poll';
  p.clock.setAttribute('datetime', plant.plant_time ?? '');
  updateAnnunciators(p.annunciators, plant.alarms ?? [], plant.zone);
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

function updateAnnunciators(a, alarms, zone) {
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
    const time = siteTime(alarm.arrived_at, zone);
    a.entries.appendChild(make(a.doc, 'li', {}, `${time} · ${alarm.label} · ${STATE_WORDS[alarm.state]}`));
  }
  if (!current.length) a.entries.appendChild(make(a.doc, 'li', {}, 'No active alarms.'));
}

// ---- Mimic -----------------------------------------------------------------

function buildMimic(doc) {
  const section = make(doc, 'section', { class: 'panel mimic', 'aria-label': 'Plant mimic' });
  const picture = svg(doc, 'svg', { viewBox: '0 0 1280 1180', role: 'img',
    'aria-label': 'Primary coolant, steam, feedwater and circulating water circuits' });
  const readings = new Map(), pumps = new Map(), modes = new Map(), fills = new Map();
  const symbols = new Map();
  const pipe = (medium, points) => {
    for (let i = 1; i < points.length; i++) {
      const [x1, y1] = points[i - 1], [x2, y2] = points[i];
      picture.appendChild(svg(doc, 'line', { x1, y1, x2, y2, class: `pipe ${medium}`, 'data-medium': medium }));
    }
  };
  const symbol = (id, x, y, w, h, draw) => {
    const g = svg(doc, 'g', { class: 'equipment', 'data-equipment': id,
      'data-bounds': `${x},${y},${w},${h}` });
    draw(g);
    picture.appendChild(g);
    symbols.set(id, g);
    return g;
  };
  const vessel = (id, x, y, reading) => symbol(id, x, y, 60, 100, (g) => {
    g.appendChild(svg(doc, 'rect', { x, y, width: 60, height: 100, rx: 24 }));
    const rods = id === 'reactor-vessel';
    const nodes = (rods ? [16, 28, 40] : [8]).map((offset) => {
      const node = svg(doc, 'rect', { x: x + offset, y: y + 50, width: rods ? 4 : 44, height: 40, class: rods ? 'rod-bank' : 'level-fill' });
      g.appendChild(node);
      return node;
    });
    fills.set(reading, { nodes, y: y + 90, height: 80, rods });
    if (id.startsWith('sg')) g.appendChild(svg(doc, 'path', { d: `M${x + 20},${y + 90} v-65 q10,-20 20,0 v65`, class: 'tube' }));
  });
  vessel('reactor-vessel', 570, 400, 'rod_position');
  symbol('core', 580, 455, 40, 30, (g) => g.appendChild(svg(doc, 'rect', { x: 580, y: 455, width: 40, height: 30, class: 'core' })));
  vessel('pressurizer', 760, 240, 'pressurizer_level');
  vessel('sg-a', 240, 400, 'sg_level_a');
  vessel('sg-b', 840, 400, 'sg_level_b');
  const pump = (id, x, y, mirror = false) => symbol(id, x - (mirror ? 26 : 16), y - 16, 42, 32, (g) => {
    g.appendChild(svg(doc, 'circle', { cx: x, cy: y, r: 16 }));
    g.appendChild(svg(doc, 'path', { d: `M${x},${y - 16} h${mirror ? -26 : 26} M${x - 6},${y + 7} l14,-7 -14,-7`, class: 'tube' }));
  });
  pump('coolant_pump_a', 270, 620); pump('coolant_pump_b', 870, 620, true);
  pump('feed_pump_a', 200, 900); pump('feed_pump_b', 960, 900);
  pump('auxiliary_feed', 500, 1080); pump('circulating_water', 900, 800);
  const valve = (id, x, y) => symbol(id, x - 14, y - 10, 28, 20, (g) => {
    g.appendChild(svg(doc, 'path', { d: `M${x - 14},${y - 10} L${x + 14},${y + 10} V${y - 10} L${x - 14},${y + 10} Z` }));
  });
  valve('feed_valve_a', 180, 460); valve('feed_valve_b', 950, 460);
  valve('turbine_valve', 930, 100); valve('steam_dump_valve', 1110, 700);
  valve('spray_valve', 715, 220); valve('pressurizer_relief', 835, 220); valve('steam_relief', 664, 40);
  for (const [id, x, w] of [['hp-turbine', 950, 40], ['lp-turbine', 1020, 50]]) {
    symbol(id, x, 85, w, 50, (g) => {
      g.appendChild(svg(doc, 'polygon', { points: `${x},100 ${x + w},85 ${x + w},135 ${x},120` }));
      g.appendChild(svg(doc, 'text', { x: x + 12, y: 115, class: 'symbol-letter' }, id.startsWith('hp') ? 'HP' : 'LP'));
    });
  }
  symbol('generator', 1100, 90, 40, 40, (g) => {
    g.appendChild(svg(doc, 'circle', { cx: 1120, cy: 110, r: 20 }));
    g.appendChild(svg(doc, 'text', { x: 1115, y: 115, class: 'symbol-letter' }, 'G'));
  });
  picture.appendChild(svg(doc, 'line', { x1: 1070, y1: 110, x2: 1100, y2: 110, class: 'shaft' }));
  symbol('condenser', 1020, 760, 120, 70, (g) => {
    g.appendChild(svg(doc, 'rect', { x: 1020, y: 760, width: 120, height: 70, rx: 8 }));
    g.appendChild(svg(doc, 'path', { d: 'M1025,790 h110 M1025,800 h110 M1025,810 h110', class: 'tube' }));
  });

  // Each circuit stops at equipment ports. Shared headers are drawn once.
  pipe('primary-hot', [[570, 420], [300, 420]]);
  pipe('primary-hot', [[630, 420], [790, 420], [840, 420]]);
  pipe('primary-hot', [[790, 340], [790, 420]]);
  pipe('primary-cold', [[270, 500], [270, 604]]);
  pipe('primary-cold', [[296, 604], [490, 604], [490, 500], [570, 500]]);
  pipe('primary-cold', [[870, 500], [870, 604]]);
  pipe('primary-cold', [[844, 604], [710, 604], [710, 500], [630, 500]]);
  pipe('primary-cold', [[760, 260], [745, 260], [745, 220], [729, 220]]);
  pipe('primary-cold', [[701, 220], [690, 220], [690, 280], [760, 280]]);
  pipe('steam', [[790, 240], [790, 220], [821, 220]]);
  pipe('steam', [[849, 220], [890, 220]]);
  pipe('steam', [[270, 400], [270, 100], [600, 100], [870, 100], [900, 100], [916, 100]]);
  pipe('steam', [[870, 400], [870, 230]]);
  pipe('steam', [[870, 210], [870, 100]]);
  // The relief branch crosses the steam riser with a visible bridge.
  picture.appendChild(svg(doc, 'path', { d: 'M870,230 Q880,220 870,210', class: 'pipe steam crossing' }));
  pipe('steam', [[600, 100], [600, 40], [650, 40]]);
  pipe('steam', [[678, 40], [710, 40]]);
  pipe('steam', [[944, 100], [950, 100]]);
  pipe('steam', [[990, 100], [1020, 100]]);
  pipe('steam', [[1060, 135], [1060, 175], [1220, 175], [1220, 780], [1140, 780]]);
  pipe('steam', [[900, 100], [900, 5], [1200, 5], [1200, 165]]);
  pipe('steam', [[1200, 185], [1200, 700], [1124, 700]]);
  picture.appendChild(svg(doc, 'path', { d: 'M1200,165 Q1210,175 1200,185', class: 'pipe steam crossing' }));
  pipe('steam', [[1096, 700], [1080, 700], [1080, 760]]);
  pipe('feedwater', [[1080, 830], [1080, 1000], [960, 1000], [200, 1000], [200, 916]]);
  pipe('feedwater', [[960, 1000], [960, 916]]);
  pipe('feedwater', [[226, 884], [226, 800], [10, 800], [10, 460], [166, 460]]);
  pipe('feedwater', [[194, 460], [240, 460]]);
  pipe('feedwater', [[986, 884], [1000, 884], [1000, 460], [964, 460]]);
  pipe('feedwater', [[936, 460], [900, 460]]);
  pipe('feedwater', [[1080, 1000], [1080, 1140], [500, 1140], [500, 1096]]);
  pipe('feedwater', [[526, 1064], [550, 1064], [550, 1010]]);
  pipe('feedwater', [[550, 990], [550, 760], [180, 760], [180, 730], [10, 730]]);
  picture.appendChild(svg(doc, 'path', { d: 'M550,1010 Q560,1000 550,990', class: 'pipe feedwater crossing' }));
  pipe('feedwater', [[550, 760], [940, 760], [940, 720], [1000, 720]]);
  pipe('circulating-water', [[820, 800], [884, 800]]);
  pipe('circulating-water', [[926, 784], [980, 784], [980, 800], [990, 800]]);
  pipe('circulating-water', [[1008, 800], [1020, 800]]);
  picture.appendChild(svg(doc, 'path', { d: 'M990,800 Q1000,790 1008,800', class: 'pipe circulating-water crossing' }));
  pipe('circulating-water', [[1140, 800], [1230, 800]]);

  const label = (text, x, y, className = 'equipment-title') => {
    const node = svg(doc, 'text', { x, y, class: className }, text);
    picture.appendChild(node);
    return node;
  };
  for (const [title, x, y] of [
    ['Reactor vessel', 510, 390], ['Pressurizer', 740, 195],
    ['Steam generator A', 100, 380], ['Steam generator B', 880, 375],
    ['Turbine', 925, 45], ['Generator', 925, 65], ['Condenser', 1100, 735],
    ['Loop A', 330, 450], ['Loop B', 740, 510],
  ]) label(title, x, y);
  const instrument = (id, x, y, tagText, mode = false) => {
    const g = svg(doc, 'g', { 'data-reading': mode ? '' : id, class: 'instrument' });
    g.appendChild(svg(doc, 'rect', { x, y, width: id === 'feed_b' ? 100 : 175, height: 52, class: 'data-box' }));
    const tag = svg(doc, 'text', { x: x + 6, y: y + 18, class: 'instrument-tag' }, tagText);
    const text = svg(doc, 'text', { x: x + 6, y: y + 40, class: 'instrument-value' });
    g.appendChild(tag); g.appendChild(text); picture.appendChild(g);
    if (mode) { text.setAttribute('data-mode', id); modes.set(id, text); }
    else readings.set(id, { text, tag, group: g });
  };
  for (const [id, x, y] of [
    ['neutron_power', 300, 480], ['rod_position', 505, 575],
    ['shutdown_rods', 505, 635], ['rod_demand', 505, 695],
    ['core_exit_temperature', 300, 540],
    ['pressurizer_pressure', 495, 180], ['pressurizer_level', 510, 300],
    ['spray_valve', 510, 115],
    ['hot_leg_a', 330, 355], ['cold_leg_a', 50, 600], ['coolant_flow_a', 310, 675],
    ['hot_leg_b', 640, 435], ['cold_leg_b', 740, 640], ['coolant_flow_b', 740, 695],
    ['sg_level_a', 50, 390], ['sg_level_b', 920, 380],
    ['steam_flow_a', 80, 285], ['steam_flow_b', 885, 310],
    ['feed_flow_a', 50, 480], ['feed_valve_a', 50, 540],
    ['feed_flow_b', 1010, 495], ['feed_valve_b', 1010, 435],
    ['steam_pressure', 340, 30], ['turbine_valve', 1010, 190],
    ['turbine_valve_position', 1010, 250], ['generator_output', 1010, 20],
    ['steam_dump_valve', 1010, 615], ['condenser_pressure', 1100, 850],
  ]) instrument(id, x, y);
  for (const [id, tag, x, y] of [
    ['pressurizer', 'PIC-455 Pressure', 495, 240],
    ['feed_a', 'LIC-421A Level', 50, 660], ['feed_b', 'LIC-421B', 885, 505],
    ['steam_dump', 'PIC-434 Pressure', 1010, 555],
  ]) instrument(id, x, y, tag, true);
  for (const [id, equipment, x, y] of [
    ['reactor_tripped', 'reactor-vessel', 550, 525], ['turbine_tripped', 'hp-turbine', 930, 155],
    ['heaters', 'pressurizer', 700, 310], ['pressurizer_relief', 'pressurizer_relief', 910, 215],
    ['steam_relief', 'steam_relief', 730, 45],
    ['coolant_pump_a', 'coolant_pump_a', 240, 660], ['coolant_pump_b', 'coolant_pump_b', 895, 590],
    ['feed_pump_a', 'feed_pump_a', 240, 915], ['feed_pump_b', 'feed_pump_b', 810, 915],
    ['auxiliary_feed', 'auxiliary_feed', 350, 1080], ['circulating_water', 'circulating_water', 790, 845],
  ]) {
    const slot = svg(doc, 'g', { class: 'state-slot', 'data-for': equipment });
    picture.appendChild(slot);
    const title = label(({ heaters: 'Heaters', pressurizer_relief: 'Relief', coolant_pump_a: 'RCP A', coolant_pump_b: 'RCP B' })[id] ?? FLAGS[id][0], x, y, 'state-label');
    const state = label('', x, y + 22, 'state-value');
    slot.appendChild(title);
    slot.appendChild(state);
    slot.setAttribute('data-slot', `${x - 2},${y - 14},${Math.max(title.textContent.length, 7) * 13 * 0.62 + 4},40`);
    state.setAttribute('data-status', id);
    const circle = symbols.get(equipment);
    circle.setAttribute('data-pump', id);
    pumps.set(id, { circle, state });
  }
  label('Primary: heavy hot leg / thin cold leg · Steam: dashed · Feedwater: thin solid · Circulating water: dash-dot', 40, 1170, 'process-key');
  section.appendChild(picture);
  return { section, readings, pumps, modes, fills, symbols };
}

function updateMimic(m, plant) {
  for (const [id, entry] of m.readings) {
    const reading = plant.readings?.[id];
    entry.tag.textContent = reading?.tag ?? '—';
    entry.group.setAttribute('aria-label', `${FIELD_LABELS[id]}: ${formatValue(reading)}`);
    entry.text.textContent = `${formatValue(reading)}${reading?.stale && reading?.value != null ? ' stale' : ''}`;
    setFlag(entry.group, 'stale', reading?.stale || reading?.value == null);
    const symbol = m.symbols.get(id);
    if (symbol) setFlag(symbol, 'stale', reading?.stale || reading?.value == null);
  }
  for (const [id, fill] of m.fills) {
    const reading = plant.readings?.[id];
    const height = reading?.value == null ? 0 : Math.max(0, Math.min(100, reading.value)) / 100 * fill.height;
    for (const node of fill.nodes) {
      node.setAttribute('y', fill.rods ? fill.y - fill.height : fill.y - height);
      node.setAttribute('height', height);
      setFlag(node, 'stale', reading?.stale || reading?.value == null);
    }
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
    setFlag(pump.circle, 'open', running === true && flag.endsWith('relief'));
  }
  for (const [id, text] of m.modes) {
    const stale = plant.links?.some((link) => link.id === (id === 'pressurizer' ? 'rcs1' : 'bop1') && !link.online);
    text.textContent = stale ? 'Stale' : ({ automatic: 'Auto', manual: 'Man' }[plant.modes?.[id]] ?? 'No data');
    setFlag(text, 'stale', stale || plant.modes?.[id] == null);
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
  let selected, selectionTimer;
  const confirmation = make(doc, 'div', { class: 'confirmation', role: 'group', 'aria-label': 'Selected action', hidden: '' });
  const note = make(doc, 'span', { role: 'status' });
  const cancel = () => {
    selected?.button.setAttribute('aria-pressed', 'false');
    selected = undefined;
    clearTimeout(selectionTimer);
    confirmation.setAttribute('hidden', '');
    note.textContent = '';
  };
  const select = (path, body, label, button, group) => {
    cancel();
    selected = { path, body, label, button, expires: Date.now() + 5000 };
    button.setAttribute('aria-pressed', 'true');
    group.appendChild(confirmation);
    confirmation.removeAttribute('hidden');
    note.textContent = `${label}: Execute or Cancel within 5 seconds.`;
    selectionTimer = setTimeout(cancel, 5000);
  };
  confirmation.appendChild(note);
  confirmation.appendChild(button(doc, 'Execute', '', () => {
    const action = selected;
    cancel();
    if (action && Date.now() < action.expires) return post(action.path, action.body, action.label, message);
    return undefined;
  }));
  confirmation.appendChild(button(doc, 'Cancel', '', cancel));
  section.appendChild(confirmation);
  for (const [path, label] of [['trip', 'Trip reactor'], ['reset', 'Reset trip']]) {
    const btn = button(doc, label, '', () => select(path, {}, label, btn, reactor.node));
    btn.setAttribute('aria-pressed', 'false');
    reactor.add(btn);
  }
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
      () => select('pump', { name: pump.name, running: toggle.next }, `${toggle.next ? 'Start' : 'Stop'} ${pump.label.toLowerCase()}`, btn, pumpGroup.node),
      `Start ${pump.label}`,
    );
    btn.setAttribute('aria-pressed', 'false');
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
      () => select('controller', { name: controller.name, auto: toggle.auto }, `${controller.label}: ${toggle.auto ? 'automatic' : 'manual'}`, btn, controllerGroup.node),
      `Set ${controller.label} to manual`,
    );
    btn.setAttribute('aria-pressed', 'false');
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
    message,
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
  pollNow.get(message)?.();
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
    const picture = svg(doc, 'svg', { viewBox: '0 0 160 40', preserveAspectRatio: 'none', class: 'sparkline', role: 'img', 'aria-label': `${trend.label} history` });
    const line = svg(doc, 'polyline', { class: 'trend-line', 'vector-effect': 'non-scaling-stroke', points: '' });
    const gaps = svg(doc, 'path', { class: 'trend-line', 'vector-effect': 'non-scaling-stroke', d: '' });
    picture.appendChild(line);
    picture.appendChild(gaps);
    item.appendChild(label);
    item.appendChild(value);
    const max = make(doc, 'span', { class: 'trend-max' });
    const min = make(doc, 'span', { class: 'trend-min' });
    item.appendChild(max);
    item.appendChild(picture);
    item.appendChild(min);
    const axis = make(doc, 'div', { class: 'time-axis' });
    axis.appendChild(make(doc, 'span', {}, '-10 min'));
    axis.appendChild(make(doc, 'span', {}, 'now'));
    item.appendChild(axis);
    section.appendChild(item);
    return { id: trend.id, rangeSpan: trend.rangeSpan, value, line, gaps, min, max };
  });
  return { section, rows };
}

function sparkSegments(samples, rangeSpan) {
  const values = samples.map((sample) => sample.value).filter(Number.isFinite);
  if (values.length < 2) return [];
  const minimum = Math.min(...values), maximum = Math.max(...values);
  const span = Math.max(maximum - minimum, rangeSpan * 0.05);
  const low = (minimum + maximum - span) / 2;
  const start = Date.parse(samples[0].time);
  const duration = Date.parse(samples.at(-1).time) - start;
  const segments = [];
  let segment = [];
  for (const [i, sample] of samples.entries()) {
    if (!Number.isFinite(sample.value)) {
      if (segment.length > 1) segments.push(segment);
      segment = [];
      continue;
    }
    const x = duration > 0 ? (Date.parse(sample.time) - start) / duration * 160 : i / (samples.length - 1) * 160;
    segment.push(`${x.toFixed(1)},${(38 - (sample.value - low) / span * 32).toFixed(1)}`);
  }
  if (segment.length > 1) segments.push(segment);
  return segments;
}

function updateTrends(t, plant, history) {
  for (const row of t.rows) {
    row.value.textContent = formatValue(plant.readings?.[row.id]);
    const samples = Array.isArray(history)
      ? history.map((sample) => ({ time: sample.plant_time, value: sample.readings?.[row.id]?.value }))
      : history[row.id]?.samples ?? [];
    const values = samples.map((s) => s.value).filter(Number.isFinite);
    const unit = plant.readings?.[row.id]?.unit ?? '';
    row.min.textContent = `Min ${values.length ? formatValue({ value: Math.min(...values), unit }) : '—'}`;
    row.max.textContent = `Max ${values.length ? formatValue({ value: Math.max(...values), unit }) : '—'}`;
    const segments = sparkSegments(samples, row.rangeSpan);
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
  s.clock.textContent = plant.plant_time
    ? siteTime(plant.plant_time, plant.zone)
    : 'Clock: waiting for the first poll';
  for (const link of plant.links ?? []) {
    const item = s.links.get(link.id);
    if (!item) continue;
    const last = link.updated_at == null ? 'never read' : `last update ${siteTime(link.updated_at, plant.zone)}`;
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
  pollNow.set(partsFor(root).controls.message, tick);
  tick();
  return setInterval(tick, interval);
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const root = document.getElementById('hmi');
  if (root) start(root);
}
