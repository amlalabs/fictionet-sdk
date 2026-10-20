// Checks the screen renderer with a fake document. Run with:
//   node --test examples/nuclear/viewer/hmi/hmi.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { render, start } from './hmi.mjs';

// A fake document: only the parts of the DOM that render() and the controls use.
class FakeNode {
  constructor(ownerDocument, tagName, namespaceURI = null) {
    this.ownerDocument = ownerDocument;
    this.tagName = tagName;
    this.namespaceURI = namespaceURI;
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.ownText = '';
    const classes = new Set();
    this.classList = {
      add: (...tokens) => tokens.forEach((token) => classes.add(token)),
      remove: (...tokens) => tokens.forEach((token) => classes.delete(token)),
      contains: (token) => classes.has(token),
    };
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  addEventListener(type, listener) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  get textContent() {
    return this.ownText + this.children.map((child) => child.textContent).join('');
  }

  set textContent(value) {
    this.children = [];
    this.ownText = String(value);
  }
}

class FakeDocument {
  createElement(tag) {
    return new FakeNode(this, tag);
  }

  createElementNS(namespace, tag) {
    return new FakeNode(this, tag, namespace);
  }
}

function fakeRoot() {
  return new FakeDocument().createElement('main');
}

function walk(node, visit) {
  visit(node);
  node.children.forEach((child) => walk(child, visit));
}

function findAll(root, predicate) {
  const found = [];
  walk(root, (node) => {
    if (predicate(node)) found.push(node);
  });
  return found;
}

function find(root, predicate) {
  const [first] = findAll(root, predicate);
  assert.ok(first, 'the element is on the screen');
  return first;
}

const byReading = (root, id) => find(root, (n) => n.getAttribute('data-reading') === id);
const byAlarm = (root, id) => find(root, (n) => n.getAttribute('data-alarm') === id);
const byButton = (root, text) => find(root, (n) => n.tagName === 'button' && n.textContent === text);
const byAria = (root, label) => find(root, (n) => n.tagName === 'button' && n.getAttribute('aria-label') === label);
const byLabel = (root, label) => find(root, (n) => n.getAttribute('aria-label') === label);

// One reply of /api/plant, as the HMI sends it at full power with one active
// alarm (relief valve open) and one acknowledged alarm (coolant pump B stopped).
const SAMPLE = {
  polls: 42,
  clock_ms: 12500,
  plant_time: '2026-03-14T08:00:12.500Z',
  links: [
    { id: 'rps1', online: true, read_ms: 12500, error: null, heartbeat: 50 },
    { id: 'rcs1', online: true, read_ms: 12000, error: null, heartbeat: 50 },
    { id: 'bop1', online: true, read_ms: 12250, error: null, heartbeat: 50 },
  ],
  readings: {
    neutron_power: { tag: "NI-41", value: 100.0, unit: '%', stale: false },
    rod_position: { tag: "ZT-401", value: 50.0, unit: '%', stale: false },
    core_exit_temperature: { tag: "TE-413", value: 325.0, unit: 'C', stale: false },
    shutdown_rods: { tag: "ZT-402", value: 0.0, unit: '%', stale: false },
    rod_demand: { tag: "ZIC-401", value: 50.0, unit: '%', stale: false },
    hot_leg_a: { tag: "TE-411A", value: 325.0, unit: 'C', stale: false },
    hot_leg_b: { tag: "TE-411B", value: 325.1, unit: 'C', stale: false },
    cold_leg_a: { tag: "TE-412A", value: 290.0, unit: 'C', stale: false },
    cold_leg_b: { tag: "TE-412B", value: 290.1, unit: 'C', stale: false },
    pressurizer_pressure: { tag: "PT-455", value: 15.5, unit: 'MPa', stale: false },
    pressurizer_level: { tag: "LT-459", value: 60.0, unit: '%', stale: false },
    coolant_flow_a: { tag: "FT-414A", value: 100.0, unit: '%', stale: false },
    coolant_flow_b: { tag: "FT-414B", value: 100.0, unit: '%', stale: false },
    spray_valve: { tag: "ZT-456", value: 0.0, unit: '%', stale: false },
    sg_level_a: { tag: "LT-421A", value: 50.0, unit: '%', stale: false },
    sg_level_b: { tag: "LT-421B", value: 50.0, unit: '%', stale: false },
    steam_pressure: { tag: "PT-431", value: 6.9, unit: 'MPa', stale: false },
    steam_flow_a: { tag: "FT-432A", value: 400.0, unit: 'kg/s', stale: false },
    steam_flow_b: { tag: "FT-432B", value: 400.0, unit: 'kg/s', stale: false },
    feed_flow_a: { tag: "FT-433A", value: 400.0, unit: 'kg/s', stale: false },
    feed_flow_b: { tag: "FT-433B", value: 400.0, unit: 'kg/s', stale: false },
    turbine_valve: { tag: "ZT-441", value: 80.0, unit: '%', stale: false },
    generator_output: { tag: "JT-451", value: 900.0, unit: 'MW', stale: false },
    condenser_pressure: { tag: "PT-452", value: 5.0, unit: 'kPa', stale: false },
    feed_valve_a: { tag: "ZT-433A", value: 40.0, unit: '%', stale: false },
    feed_valve_b: { tag: "ZT-433B", value: 40.0, unit: '%', stale: false },
    turbine_valve_position: { tag: "ZIC-441", value: 80.0, unit: '%', stale: false },
    steam_dump_valve: { tag: "ZT-434", value: 0.0, unit: '%', stale: false },
  },
  status: {
    reactor_tripped: false,
    coolant_pump_a: true,
    coolant_pump_b: false,
    pressurizer_relief: true,
    heaters: true,
    feed_pump_a: true,
    feed_pump_b: true,
    auxiliary_feed: false,
    circulating_water: true,
    steam_relief: false,
    turbine_tripped: false,
  },
  modes: {
    pressurizer: 'automatic',
    feed_a: 'automatic',
    feed_b: 'automatic',
    steam_dump: 'automatic',
  },
  alarms: [
    { id: 'subcooling_margin_low', label: 'Subcooling margin low', state: 'normal', in_ms: null },
    { id: 'pressurizer_pressure_high', label: 'Pressurizer pressure high', state: 'normal', in_ms: null },
    { id: 'pressurizer_pressure_low', label: 'Pressurizer pressure low', state: 'normal', in_ms: null },
    { id: 'pressurizer_level_high', label: 'Pressurizer level high', state: 'normal', in_ms: null },
    { id: 'pressurizer_level_low', label: 'Pressurizer level low', state: 'normal', in_ms: null },
    { id: 'hot_leg_high', label: 'Hot leg temperature high', state: 'normal', in_ms: null },
    { id: 'sg_level_low', label: 'Steam generator level low', state: 'normal', in_ms: null },
    { id: 'sg_level_high', label: 'Steam generator level high', state: 'normal', in_ms: null },
    { id: 'coolant_flow_low', label: 'Coolant flow low', state: 'normal', in_ms: null },
    { id: 'condenser_pressure_high', label: 'Condenser pressure high', state: 'normal', in_ms: null },
    { id: 'neutron_power_high', label: 'Neutron power high', state: 'normal', in_ms: null },
    { id: 'reactor_tripped', label: 'Reactor tripped', state: 'normal', in_ms: null },
    { id: 'turbine_tripped', label: 'Turbine tripped', state: 'normal', in_ms: null },
    { id: 'coolant_pump_stopped', label: 'Coolant pump stopped', state: 'acknowledged', in_ms: 10000 },
    { id: 'feed_pump_stopped', label: 'Feed pump stopped', state: 'normal', in_ms: null },
    { id: 'relief_open', label: 'Relief valve open', state: 'active', in_ms: 10000 },
  ],
};

// A copy of the sample with one reading changed, for the trend history.
function sampleAt(neutronPower) {
  const copy = structuredClone(SAMPLE);
  copy.readings.neutron_power.value = neutronPower;
  return copy;
}

// The page's fetch, replaced by a fake that records each request.
function withFetch(reply, body, run) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url, method: options.method ?? 'GET', body: options.body ? JSON.parse(options.body) : null });
    return {
      ok: reply.status < 400,
      status: reply.status,
      json: async () => body,
    };
  };
  return run(calls).finally(() => {
    globalThis.fetch = original;
  });
}

test('the mimic shows live readings with their units', () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  assert.match(byReading(root, 'pressurizer_pressure').textContent, /15\.50 MPa/);
  assert.match(byReading(root, 'neutron_power').textContent, /100\.0 %/);
  assert.match(byReading(root, 'hot_leg_a').textContent, /325\.0 C/);
});

test('the mimic shows each pump as running or stopped', () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  const pumpA = find(root, (n) => n.getAttribute('data-pump') === 'coolant_pump_a');
  const pumpB = find(root, (n) => n.getAttribute('data-pump') === 'coolant_pump_b');
  assert.ok(pumpA.classList.contains('running'));
  assert.ok(pumpB.classList.contains('stopped'));
  assert.ok(!pumpB.classList.contains('running'));
  assert.ok(findAll(root, (n) => n.textContent === 'Stopped').length >= 1);
});

test('the alarm strip has one tile per alarm, in its state', () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  const tiles = findAll(root, (n) => n.getAttribute('data-alarm') !== null);
  assert.equal(tiles.length, SAMPLE.alarms.length);
  const relief = byAlarm(root, 'relief_open');
  assert.ok(relief.classList.contains('active'));
  assert.equal(relief.textContent, 'Relief valve openActive');
  assert.ok(byAlarm(root, 'coolant_pump_stopped').classList.contains('acknowledged'));
  assert.ok(byAlarm(root, 'reactor_tripped').classList.contains('normal'));
  assert.ok(!byAlarm(root, 'reactor_tripped').classList.contains('active'));
  assert.equal(find(root, (n) => n.textContent === '1 active').tagName, 'span');
});

test('each trend is a line over the history it is given', () => {
  const root = fakeRoot();
  const history = [sampleAt(99.0), sampleAt(99.5), sampleAt(100.0)];
  render(root, SAMPLE, history);
  const lines = findAll(root, (n) => n.tagName === 'polyline');
  assert.equal(lines.length, 6, 'one sparkline per trend');
  const power = lines[0];
  const points = power.getAttribute('points').split(' ');
  assert.equal(points.length, 3, 'one point per sample');
  assert.match(points[0], /^0\.0,/, 'the oldest sample is at the left');
  assert.match(points[2], /^160\.0,/, 'the newest sample is at the right');
});

test('a trend with one sample has no line yet', () => {
  const root = fakeRoot();
  render(root, SAMPLE, [SAMPLE]);
  for (const line of findAll(root, (n) => n.tagName === 'polyline')) {
    assert.equal(line.getAttribute('points'), '');
  }
});

test('the status bar shows the clock, each controller and the heartbeat', () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  find(root, (n) => n.textContent === 'Elapsed 12.5 s');
  assert.ok(!root.textContent.includes('Heartbeat 42'));
  find(root, (n) => n.textContent === 'rcs1 COMM OK, last poll 12.0 s, heartbeat 50');
});

test('a controller that was never read shows dashes and no values', () => {
  const root = fakeRoot();
  const unread = structuredClone(SAMPLE);
  unread.clock_ms = null;
  unread.plant_time = null;
  unread.polls = 0;
  unread.links = unread.links.map((link) => ({ ...link, online: false, read_ms: null, heartbeat: null }));
  for (const reading of Object.values(unread.readings)) {
    reading.value = null;
    reading.stale = true;
  }
  for (const id of Object.keys(unread.status)) unread.status[id] = null;
  render(root, unread, []);
  assert.equal(byReading(root, 'pressurizer_pressure').textContent, 'PT-455 Pressure: —');
  find(root, (n) => n.textContent === 'Clock: waiting for the first poll');
  find(root, (n) => n.textContent === 'rcs1 COMM FAIL: awaiting first poll, never read, heartbeat not yet read');
  assert.ok(byReading(root, 'pressurizer_pressure').classList.contains('stale'));
});

test('the controls keep their elements between renders', () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  const rod = byLabel(root, 'Rod demand (%)');
  render(root, SAMPLE, []);
  assert.equal(byLabel(root, 'Rod demand (%)'), rod, 'the same input after a second render');
});

test('render makes no network calls', () => {
  const original = globalThis.fetch;
  globalThis.fetch = () => {
    throw new Error('render must not fetch');
  };
  try {
    const root = fakeRoot();
    render(root, SAMPLE, [SAMPLE, sampleAt(100.0)]);
    assert.ok(byReading(root, 'neutron_power'));
  } finally {
    globalThis.fetch = original;
  }
});

test('the trip button posts to the trip control', async () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  await withFetch({ status: 200 }, { ok: true }, async (calls) => {
    await byButton(root, 'Trip reactor').listeners.get('click')[0]();
    assert.deepEqual(calls, [], 'arming sends nothing');
    assert.match(byLabel(root, 'Confirm trip').textContent, /Confirm trip/);
    await byButton(root, 'Confirm trip').listeners.get('click')[0]();
    assert.deepEqual(calls, [{ url: '/api/control/trip', method: 'POST', body: {} }]);
    assert.equal(find(root, (n) => n.classList.contains('message')).textContent, 'Trip reactor: done');
  });
});

test('the rod demand button posts the percent typed in the field', async () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  await withFetch({ status: 200 }, { ok: true }, async (calls) => {
    byLabel(root, 'Rod demand (%)').value = '40';
    await byAria(root, 'Set rod demand').listeners.get('click')[0]();
    assert.deepEqual(calls, [
      { url: '/api/control/rod-demand', method: 'POST', body: { percent: 40 } },
    ]);
  });
});

test('an empty field posts nothing and asks for a percent', async () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  await withFetch({ status: 200 }, { ok: true }, async (calls) => {
    byLabel(root, 'Rod demand (%)').value = '';
    await byAria(root, 'Set rod demand').listeners.get('click')[0]();
    assert.deepEqual(calls, []);
    assert.equal(
      find(root, (n) => n.classList.contains('message')).textContent,
      'Rod demand (%): enter a percent from 0 to 100',
    );
  });
});

test('a refused control shows the controller reason', async () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  await withFetch(
    { status: 400 },
    { ok: false, reason: 'illegal data value', exception: 3 },
    async (calls) => {
      byLabel(root, 'Feed valve A demand (%)').value = '30';
      await byAria(root, 'Set Feed valve A').listeners.get('click')[0]();
      assert.equal(calls[0].url, '/api/control/valve');
      assert.deepEqual(calls[0].body, { name: 'feed-a', percent: 30 });
      assert.equal(
        find(root, (n) => n.classList.contains('message')).textContent,
        'Feed valve A refused: illegal data value',
      );
    },
  );
});

test('the pump button starts a stopped pump and stops a running one', async () => {
  const root = fakeRoot();
  render(root, SAMPLE, []);
  await withFetch({ status: 200 }, { ok: true }, async (calls) => {
    // Coolant pump B is stopped, so its button offers to start it.
    const startButtons = findAll(root, (n) => n.tagName === 'button' && n.textContent === 'Start');
    assert.equal(startButtons.length, 2, 'coolant pump B and the auxiliary feed pump');
    await startButtons[0].listeners.get('click')[0]();
    assert.deepEqual(calls[0], {
      url: '/api/control/pump',
      method: 'POST',
      body: { name: 'coolant-b', running: true },
    });
  });
});

test('the subcooling margin tile follows its state', () => {
  const root = fakeRoot();
  const plant = structuredClone(SAMPLE);
  plant.alarms.find((alarm) => alarm.id === 'subcooling_margin_low').state = 'active';
  render(root, plant, []);
  assert.ok(byAlarm(root, 'subcooling_margin_low').classList.contains('active'));
});

test('a null link heartbeat is not yet read', () => {
  const root = fakeRoot();
  const plant = structuredClone(SAMPLE);
  plant.links[0].heartbeat = null;
  render(root, plant, []);
  find(root, (n) => n.textContent === 'rps1 COMM OK, last poll 12.5 s, heartbeat not yet read');
});


test('every analog and discrete state appears on the mimic', () => {
  const root = fakeRoot();
  render(root, SAMPLE);
  for (const [id, reading] of Object.entries(SAMPLE.readings)) {
    assert.ok(byReading(root, id).textContent.includes(reading.tag));
  }
  for (const id of Object.keys(SAMPLE.status)) {
    find(root, (node) => node.getAttribute('data-status') === id);
  }
  find(root, (node) => node.tagName === 'time' && node.textContent === SAMPLE.plant_time);
});

test('alarm summary keeps the arrival time for active and acknowledged alarms', () => {
  const root = fakeRoot();
  render(root, SAMPLE);
  const entries = find(root, (node) => node.classList.contains('alarm-entries'));
  assert.equal(entries.children.length, 2);
  assert.match(entries.textContent, /0:10.0 · Relief valve open · Active/);
  assert.match(entries.textContent, /0:10.0 · Coolant pump stopped · Acknowledged/);
  render(root, { ...SAMPLE, alarms: SAMPLE.alarms.map((a) => ({ ...a, state: 'normal', in_ms: null })) });
  assert.equal(entries.textContent, 'No active alarms.');
});

test('link failures use the classified reason', () => {
  for (const error of ['timeout', 'refused', 'bad reply']) {
    const root = fakeRoot();
    render(root, { ...SAMPLE, links: [{ ...SAMPLE.links[0], online: false, error }] });
    assert.ok(root.textContent.includes(`rps1 COMM FAIL: ${error}`));
  }
});

test('trip arming expires and requires a new confirmation', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const root = fakeRoot();
  render(root, SAMPLE);
  await withFetch({ status: 200 }, { ok: true }, async (calls) => {
    await byButton(root, 'Trip reactor').listeners.get('click')[0]();
    assert.match(find(root, (n) => n.getAttribute('id') === 'trip-note').textContent, /5 seconds/);
    t.mock.timers.tick(5001);
    await byButton(root, 'Trip reactor').listeners.get('click')[0]();
    assert.deepEqual(calls, []);
    await byButton(root, 'Confirm trip').listeners.get('click')[0]();
    assert.equal(calls.length, 1);
  });
});

// The mimic uses a fixed monospace font. Its text rectangles follow the DOM
// coordinates, actual strings, and the font's advance with a safety margin.
function textRect(node) {
  const x = Number(node.getAttribute('x'));
  const y = Number(node.getAttribute('y'));
  return { x: x - 1, y: y - 14, w: node.textContent.length * 8 + 2, h: 18 };
}
function overlaps(a, b) {
  return a.x < b.x + b.w && a.x + a.w > b.x && a.y < b.y + b.h && a.y + a.h > b.y;
}
function segmentHitsRect(line, box) {
  const x = Number(line.getAttribute('x1'));
  const y = Number(line.getAttribute('y1'));
  const dx = Number(line.getAttribute('x2')) - x;
  const dy = Number(line.getAttribute('y2')) - y;
  let lo = 0, hi = 1;
  for (const [p, q] of [[-dx, x - box.x], [dx, box.x + box.w - x], [-dy, y - box.y], [dy, box.y + box.h - y]]) {
    if (p === 0) { if (q < 0) return false; }
    else if (p < 0) lo = Math.max(lo, q / p);
    else hi = Math.min(hi, q / p);
  }
  return lo <= hi;
}

test('mimic text boxes stay clear of pipes, other text, and neighboring equipment', () => {
  for (const missing of [false, true]) {
    const plant = structuredClone(SAMPLE);
    if (missing) {
      for (const r of Object.values(plant.readings)) r.value = null;
      for (const id of Object.keys(plant.status)) plant.status[id] = null;
    }
    const root = fakeRoot();
    render(root, plant);
    const mimic = find(root, (n) => n.classList.contains('mimic'));
    const texts = findAll(mimic, (n) => n.tagName === 'text');
    const pipes = findAll(mimic, (n) => n.classList.contains('pipe'));
    const equipment = findAll(mimic, (n) => n.classList.contains('equipment')).map((n) => ({
      x: +n.getAttribute('x'), y: +n.getAttribute('y'), w: +n.getAttribute('width'), h: +n.getAttribute('height'),
    }));
    for (const [i, node] of texts.entries()) {
      const box = textRect(node);
      assert.ok(equipment.some((e) => box.x > e.x && box.x + box.w < e.x + e.w && box.y > e.y && box.y + box.h < e.y + e.h), node.textContent);
      for (const pipe of pipes) assert.ok(!segmentHitsRect(pipe, box), `pipe crosses ${node.textContent}`);
      for (const other of texts.slice(i + 1)) assert.ok(!overlaps(box, textRect(other)), `${node.textContent} overlaps ${other.textContent}`);
    }
    for (const [i, box] of equipment.entries()) {
      for (const other of equipment.slice(i + 1)) assert.ok(!overlaps(box, other));
    }
  }
});

test('a reload fetches server history and draws it on the first poll', async () => {
  const originalFetch = globalThis.fetch;
  const originalInterval = globalThis.setInterval;
  const calls = [];
  let complete;
  globalThis.setInterval = () => 0;
  globalThis.fetch = async (url) => {
    calls.push(url);
    return { ok: true, json: async () => url === '/api/plant' ? SAMPLE : {
      point: new URL(url, 'http://hmi01').searchParams.get('point'),
      samples: [{ clock_ms: 1000, value: 90 }, { clock_ms: 2000, value: 100 }],
    } };
  };
  try {
    for (let i = 0; i < 2; i++) {
      const root = fakeRoot();
      start(root);
      // Flush the fetch and render promise chain without a timer.
      complete = new Promise((resolve) => setImmediate(resolve));
      await complete;
      assert.equal(findAll(root, (n) => n.tagName === 'polyline')[0].getAttribute('points').split(' ').length, 2);
    }
    assert.equal(calls.filter((url) => url.startsWith('/api/trend?')).length, 12);
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.setInterval = originalInterval;
  }
});


test('history uses timestamps and leaves failed reads as gaps', () => {
  const root = fakeRoot();
  render(root, SAMPLE, { neutron_power: { samples: [
    { clock_ms: 0, value: 90 }, { clock_ms: 1000, value: 95 },
    { clock_ms: 2000, value: null },
    { clock_ms: 3000, value: 97 }, { clock_ms: 4000, value: 100 },
  ] } });
  const line = findAll(root, (n) => n.tagName === 'polyline')[0];
  assert.equal(line.getAttribute('points'), '0.0,38.0 40.0,22.0');
  const path = findAll(root, (n) => n.tagName === 'path')[0];
  assert.equal(path.getAttribute('d'), 'M120.0,15.6 L160.0,6.0');
});

test('held equipment states are marked stale after a link failure', () => {
  const root = fakeRoot();
  const plant = structuredClone(SAMPLE);
  plant.links[1].online = false;
  plant.links[1].error = 'timeout';
  render(root, plant);
  for (const id of ['coolant_pump_a', 'coolant_pump_b', 'heaters', 'pressurizer_relief']) {
    const state = find(root, (n) => n.getAttribute('data-status') === id);
    assert.equal(state.textContent, 'Stale');
    assert.ok(state.classList.contains('stale'));
  }
});
