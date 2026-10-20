// Checks the screen renderer with a fake document. Run with:
//   node --test examples/nuclear/viewer/hmi/hmi.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const styles = readFileSync(new URL('./hmi.css', import.meta.url), 'utf8');
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

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  appendChild(child) {
    if (child.parentNode) child.parentNode.children.splice(child.parentNode.children.indexOf(child), 1);
    child.parentNode = this;
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
  zone: 'GMT',
  plant_time: '2026-03-14T07:43:24.500+00:00',
  links: [
    { id: 'rps1', online: true, updated_at: '2026-03-14T07:43:24.500+00:00', error: null, heartbeat: 50 },
    { id: 'rcs1', online: true, updated_at: '2026-03-14T07:43:24.000+00:00', error: null, heartbeat: 50 },
    { id: 'bop1', online: true, updated_at: '2026-03-14T07:43:24.250+00:00', error: null, heartbeat: 50 },
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
    { id: 'subcooling_margin_low', label: 'Subcooling margin low', state: 'normal', arrived_at: null },
    { id: 'pressurizer_pressure_high', label: 'Pressurizer pressure high', state: 'normal', arrived_at: null },
    { id: 'pressurizer_pressure_low', label: 'Pressurizer pressure low', state: 'normal', arrived_at: null },
    { id: 'pressurizer_level_high', label: 'Pressurizer level high', state: 'normal', arrived_at: null },
    { id: 'pressurizer_level_low', label: 'Pressurizer level low', state: 'normal', arrived_at: null },
    { id: 'hot_leg_high', label: 'Hot leg temperature high', state: 'normal', arrived_at: null },
    { id: 'sg_level_low', label: 'Steam generator level low', state: 'normal', arrived_at: null },
    { id: 'sg_level_high', label: 'Steam generator level high', state: 'normal', arrived_at: null },
    { id: 'coolant_flow_low', label: 'Coolant flow low', state: 'normal', arrived_at: null },
    { id: 'condenser_pressure_high', label: 'Condenser pressure high', state: 'normal', arrived_at: null },
    { id: 'neutron_power_high', label: 'Neutron power high', state: 'normal', arrived_at: null },
    { id: 'reactor_tripped', label: 'Reactor tripped', state: 'normal', arrived_at: null },
    { id: 'turbine_tripped', label: 'Turbine tripped', state: 'normal', arrived_at: null },
    { id: 'coolant_pump_stopped', label: 'Coolant pump stopped', state: 'acknowledged', arrived_at: '2026-03-14T07:43:22.000+00:00' },
    { id: 'feed_pump_stopped', label: 'Feed pump stopped', state: 'normal', arrived_at: null },
    { id: 'relief_open', label: 'Relief valve open', state: 'active', arrived_at: '2026-03-14T07:43:22.000+00:00' },
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
  find(root, (n) => n.textContent === '07:43:24 GMT');
  assert.ok(!root.textContent.includes('Heartbeat 42'));
  find(root, (n) => n.textContent === 'rcs1 COMM OK, last update 07:43:24 GMT, heartbeat 50');
});

test('a controller that was never read shows dashes and no values', () => {
  const root = fakeRoot();
  const unread = structuredClone(SAMPLE);
  unread.plant_time = null;
  unread.links = unread.links.map((link) => ({ ...link, online: false, updated_at: null, heartbeat: null }));
  for (const reading of Object.values(unread.readings)) {
    reading.value = null;
    reading.stale = true;
  }
  for (const id of Object.keys(unread.status)) unread.status[id] = null;
  render(root, unread, []);
  assert.equal(byReading(root, 'pressurizer_pressure').textContent, 'PT-455—');
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
    assert.match(byLabel(root, 'Selected action').textContent, /Trip reactor: Execute or Cancel/);
    assert.equal(byLabel(root, 'Selected action').getAttribute('hidden'), null);
    await byButton(root, 'Execute').listeners.get('click')[0]();
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
    assert.deepEqual(calls, []);
    await byButton(root, 'Execute').listeners.get('click')[0]();
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
  find(root, (n) => n.textContent === 'rps1 COMM OK, last update 07:43:24 GMT, heartbeat not yet read');
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
  find(root, (node) => node.tagName === 'time' && node.textContent === '07:43:24 GMT');
});

test('alarm summary keeps the arrival time for active and acknowledged alarms', () => {
  const root = fakeRoot();
  render(root, SAMPLE);
  const entries = find(root, (node) => node.classList.contains('alarm-entries'));
  assert.equal(entries.children.length, 2);
  assert.match(entries.textContent, /07:43:22 GMT · Relief valve open · Active/);
  assert.match(entries.textContent, /07:43:22 GMT · Coolant pump stopped · Acknowledged/);
  render(root, { ...SAMPLE, alarms: SAMPLE.alarms.map((a) => ({ ...a, state: 'normal', arrived_at: null })) });
  assert.equal(entries.textContent, 'No active alarms.');
});

test('link failures use the classified reason', () => {
  for (const error of ['timeout', 'refused', 'bad reply']) {
    const root = fakeRoot();
    render(root, { ...SAMPLE, links: [{ ...SAMPLE.links[0], online: false, error }] });
    assert.ok(root.textContent.includes(`rps1 COMM FAIL: ${error}`));
  }
});

test('selection expires and requires a new confirmation', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const root = fakeRoot();
  render(root, SAMPLE);
  await withFetch({ status: 200 }, { ok: true }, async (calls) => {
    await byButton(root, 'Trip reactor').listeners.get('click')[0]();
    assert.match(byLabel(root, 'Selected action').textContent, /5 seconds/);
    t.mock.timers.tick(5001);
    assert.equal(byLabel(root, 'Selected action').getAttribute('hidden'), '');
    await byButton(root, 'Execute').listeners.get('click')[0]();
    assert.deepEqual(calls, []);
    await byButton(root, 'Trip reactor').listeners.get('click')[0]();
    assert.deepEqual(calls, []);
    await byButton(root, 'Execute').listeners.get('click')[0]();
    assert.equal(calls.length, 1);
  });
});

// The mimic uses a fixed monospace font. Its text rectangles follow the DOM
// coordinates, actual strings, and the font's advance with a safety margin.
function textRect(node) {
  const x = Number(node.getAttribute('x'));
  const y = Number(node.getAttribute('y'));
  const em = node.classList.contains('instrument-value') ? 15 : 13;
  return { x, y: y - em * 0.9, w: node.textContent.length * em * 0.62, h: em * 1.2 };
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
  for (const quality of ['live', 'on', 'off', 'missing', 'stale']) {
    const plant = structuredClone(SAMPLE);
    if (quality === 'on' || quality === 'off') for (const id of Object.keys(plant.status)) plant.status[id] = quality === 'on';
    if (quality === 'stale') {
      for (const r of Object.values(plant.readings)) r.stale = true;
      for (const link of plant.links) link.online = false;
    }
    if (quality === 'missing') {
      for (const r of Object.values(plant.readings)) r.value = null;
      for (const id of Object.keys(plant.status)) plant.status[id] = null;
    }
    const root = fakeRoot();
    render(root, plant);
    const mimic = find(root, (n) => n.classList.contains('mimic'));
    const texts = findAll(mimic, (n) => n.tagName === 'text');
    const pipes = findAll(mimic, (n) => n.classList.contains('pipe'));
    const equipment = findAll(mimic, (n) => n.getAttribute('data-bounds')).map((n) => {
      const [x, y, w, h] = n.getAttribute('data-bounds').split(',').map(Number);
      return { x, y, w, h };
    });
    const boxes = findAll(mimic, (n) => n.classList.contains('data-box')).map((n) => ({
      x: +n.getAttribute('x'), y: +n.getAttribute('y'), w: +n.getAttribute('width'), h: +n.getAttribute('height'),
    }));
    assert.equal(boxes.length, Object.keys(SAMPLE.readings).length + Object.keys(SAMPLE.modes).length);
    const slots = findAll(mimic, (n) => n.classList.contains('state-slot'));
    assert.equal(slots.length, Object.keys(SAMPLE.status).length);
    for (const slot of slots) {
      const [x, y, w, h] = slot.getAttribute('data-slot').split(',').map(Number);
      const area = { x, y, w, h };
      assert.ok(find(mimic, (n) => n.getAttribute('data-equipment') === slot.getAttribute('data-for')));
      for (const text of slot.children) {
        const b = textRect(text);
        assert.ok(b.x >= x && b.y >= y && b.x + b.w <= x + w && b.y + b.h <= y + h, text.textContent);
      }
      for (const b of [...boxes, ...equipment]) assert.ok(!overlaps(area, b), `Slot ${slot.textContent} overlaps an obstacle`);
      for (const text of texts.filter((n) => n.parentNode !== slot)) assert.ok(!overlaps(area, textRect(text)), `Slot overlaps ${text.textContent}`);
      for (const line of pipeSegments(mimic)) assert.ok(!segmentHitsRect(line, area), `Line enters ${slot.textContent}`);
    }
    for (const [i, box] of boxes.entries()) {
      for (const pipe of pipes) assert.ok(!segmentHitsRect(pipe, box), `pipe crosses box ${i}`);
      for (const other of boxes.slice(i + 1)) assert.ok(!overlaps(box, other), `box ${i} overlaps another box`);
      for (const symbol of equipment) assert.ok(!overlaps(box, symbol), `box ${i} overlaps equipment`);
    }
    for (const [i, node] of texts.entries()) {
      const box = textRect(node);
      if (node.classList.contains('instrument-tag') || node.classList.contains('instrument-value')) {
        assert.ok(boxes.some((e) => box.x > e.x && box.x + box.w < e.x + e.w && box.y > e.y && box.y + box.h < e.y + e.h), node.textContent);
        for (const pipe of pipes) assert.ok(!segmentHitsRect(pipe, box), `pipe crosses ${node.textContent}`);
      }
      if (!node.classList.contains('symbol-letter')) {
        for (const symbol of equipment) assert.ok(!overlaps(box, symbol), `${node.textContent} overlaps equipment`);
      }
      if (!node.classList.contains('instrument-tag') && !node.classList.contains('instrument-value')) {
        for (const data of boxes) assert.ok(!overlaps(box, data), `${node.textContent} overlaps a data box`);
        for (const pipe of pipeSegments(mimic)) assert.ok(!segmentHitsRect(pipe, box), `pipe crosses ${node.textContent}`);
      }
      for (const other of texts.slice(i + 1)) assert.ok(!overlaps(box, textRect(other)), `${node.textContent} overlaps ${other.textContent}`);
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
      samples: [{ time: '2026-03-14T07:43:13.000+00:00', value: 90 }, { time: '2026-03-14T07:43:14.000+00:00', value: 100 }],
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
    { time: '2026-03-14T07:43:12.000+00:00', value: 90 }, { time: '2026-03-14T07:43:13.000+00:00', value: 95 },
    { time: '2026-03-14T07:43:14.000+00:00', value: null },
    { time: '2026-03-14T07:43:15.000+00:00', value: 97 }, { time: '2026-03-14T07:43:16.000+00:00', value: 100 },
  ] } });
  const line = findAll(root, (n) => n.tagName === 'polyline')[0];
  assert.equal(line.getAttribute('points'), '0.0,38.0 40.0,22.0');
  const path = findAll(root, (n) => n.tagName === 'path' && n.classList.contains('trend-line'))[0];
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


test('all visible times use the site zone without elapsed counters', () => {
  const root = fakeRoot();
  const plant = structuredClone(SAMPLE);
  plant.zone = 'IST';
  plant.plant_time = '2026-03-14T13:13:24.500+05:30';
  plant.links.forEach((link) => { link.updated_at = plant.plant_time; });
  plant.alarms.forEach((alarm) => {
    if (alarm.arrived_at) alarm.arrived_at = '2026-03-14T13:13:22.000+05:30';
  });
  render(root, plant);
  assert.ok(root.textContent.includes('13:13:24 IST'));
  assert.ok(root.textContent.includes('last update 13:13:24 IST'));
  assert.ok(root.textContent.includes('13:13:22 IST · Relief valve open'));
  assert.doesNotMatch(root.textContent, /Elapsed|last poll|clock_ms|read_ms|in_ms|polls|\d+\.\d+ s\b/);
  const clock = find(root, (node) => node.tagName === 'time');
  assert.equal(clock.getAttribute('datetime'), plant.plant_time);
});


test('the process graphic has equipment symbols and distinct process media', () => {
  const root = fakeRoot();
  render(root, SAMPLE);
  for (const id of ['reactor-vessel', 'core', 'pressurizer', 'sg-a', 'sg-b', 'coolant_pump_a', 'coolant_pump_b', 'feed_pump_a', 'feed_pump_b', 'auxiliary_feed', 'circulating_water', 'feed_valve_a', 'feed_valve_b', 'turbine_valve', 'steam_dump_valve', 'spray_valve', 'pressurizer_relief', 'steam_relief', 'hp-turbine', 'lp-turbine', 'generator', 'condenser']) {
    const symbol = find(root, (n) => n.getAttribute('data-equipment') === id);
    assert.ok(symbol.children.length);
    if (id.includes('pump') || ['auxiliary_feed', 'circulating_water', 'generator'].includes(id)) assert.ok(symbol.children.some((n) => n.tagName === 'circle'));
    if (id.endsWith('turbine')) assert.ok(symbol.children.some((n) => n.tagName === 'polygon'));
    if (id.includes('valve') || id.endsWith('relief')) assert.ok(symbol.children.some((n) => n.tagName === 'path' && n.getAttribute('d').endsWith('Z')));
  }
  for (const medium of ['primary-hot', 'primary-cold', 'steam', 'feedwater', 'circulating-water']) {
    assert.ok(findAll(root, (n) => n.getAttribute('data-medium') === medium).length > 1);
  }
  for (const [id, mode] of Object.entries(SAMPLE.modes)) assert.equal(find(root, (n) => n.getAttribute('data-mode') === id).textContent, mode === 'automatic' ? 'Auto' : 'Man');
});

test('trip, reset, pump stop and mode changes select, cancel and execute once', async () => {
  for (const [label, path, body] of [
    ['Trip reactor', 'trip', {}], ['Reset trip', 'reset', {}],
    ['Stop Coolant pump A', 'pump', { name: 'coolant-a', running: false }],
    ['Set Pressurizer pressure control to manual', 'controller', { name: 'pressurizer', auto: false }],
  ]) {
    const root = fakeRoot();
    render(root, SAMPLE);
    await withFetch({ status: 200 }, { ok: true }, async (calls) => {
      await byAria(root, label).listeners.get('click')[0]();
      assert.deepEqual(calls, []);
      assert.equal(byLabel(root, 'Selected action').getAttribute('hidden'), null);
      await byButton(root, 'Cancel').listeners.get('click')[0]();
      await byButton(root, 'Execute').listeners.get('click')[0]();
      assert.deepEqual(calls, []);
      await byAria(root, label).listeners.get('click')[0]();
      await byButton(root, 'Execute').listeners.get('click')[0]();
      await byButton(root, 'Execute').listeners.get('click')[0]();
      assert.deepEqual(calls, [{ url: `/api/control/${path}`, method: 'POST', body }]);
    });
  }
});

test('only the latest selection executes and polling does not change its command', async () => {
  const root = fakeRoot();
  render(root, SAMPLE);
  await withFetch({ status: 200 }, { ok: true }, async (calls) => {
    await byButton(root, 'Trip reactor').listeners.get('click')[0]();
    await byAria(root, 'Stop Coolant pump A').listeners.get('click')[0]();
    const changed = structuredClone(SAMPLE);
    changed.status.coolant_pump_a = false;
    render(root, changed);
    await byButton(root, 'Execute').listeners.get('click')[0]();
    assert.deepEqual(calls, [{ url: '/api/control/pump', method: 'POST', body: { name: 'coolant-a', running: false } }]);
  });
});

test('trends stretch strokes without stretching axis text', () => {
  const root = fakeRoot();
  render(root, SAMPLE, [sampleAt(90), sampleAt(100)]);
  const plots = findAll(root, (n) => n.classList.contains('sparkline'));
  assert.equal(plots.length, 6);
  for (const plot of plots) {
    assert.equal(plot.getAttribute('preserveAspectRatio'), 'none');
    for (const line of plot.children) assert.equal(line.getAttribute('vector-effect'), 'non-scaling-stroke');
    assert.equal(findAll(plot, (n) => n.tagName === 'text').length, 0);
  }
  assert.equal(findAll(root, (n) => n.classList.contains('trend-min'))[0].textContent, 'Min 90.0 %');
  assert.equal(findAll(root, (n) => n.classList.contains('trend-max'))[0].textContent, 'Max 100.0 %');
  assert.equal(findAll(root, (n) => n.textContent === '-10 min').length, 6);
  assert.equal(findAll(root, (n) => n.textContent === 'now').length, 6);
});


test('every pump direction and controller mode requires execution', async () => {
  for (const enabled of [false, true]) {
    const root = fakeRoot();
    const plant = structuredClone(SAMPLE);
    for (const id of Object.keys(plant.status)) plant.status[id] = enabled;
    for (const id of Object.keys(plant.modes)) plant.modes[id] = enabled ? 'automatic' : 'manual';
    render(root, plant);
    await withFetch({ status: 200 }, { ok: true }, async (calls) => {
      for (const [name, label] of [['coolant-a', 'Coolant pump A'], ['coolant-b', 'Coolant pump B'], ['feed-a', 'Feed pump A'], ['feed-b', 'Feed pump B'], ['aux-feed', 'Auxiliary feed pump'], ['circ-water', 'Circulating water pump']]) {
        const before = calls.length;
        await byAria(root, `${enabled ? 'Stop' : 'Start'} ${label}`).listeners.get('click')[0]();
        assert.equal(calls.length, before);
        await byButton(root, 'Execute').listeners.get('click')[0]();
        assert.equal(calls.length, before + 1);
        assert.deepEqual(calls.at(-1), { url: '/api/control/pump', method: 'POST', body: { name, running: !enabled } });
      }
      for (const [name, label] of [['pressurizer', 'Pressurizer pressure control'], ['feed-a', 'Feed level control A'], ['feed-b', 'Feed level control B'], ['steam-dump', 'Steam dump control']]) {
        const before = calls.length;
        await byAria(root, `Set ${label} to ${enabled ? 'manual' : 'automatic'}`).listeners.get('click')[0]();
        assert.equal(calls.length, before);
        await byButton(root, 'Execute').listeners.get('click')[0]();
        assert.equal(calls.length, before + 1);
        assert.deepEqual(calls.at(-1), { url: '/api/control/controller', method: 'POST', body: { name, auto: !enabled } });
      }
    });
  }
});


test('vessel fills and rod bars follow values and retain quality marks', () => {
  const root = fakeRoot();
  const plant = structuredClone(SAMPLE);
  render(root, plant);
  const vessel = (id) => find(root, (n) => n.getAttribute('data-equipment') === id);
  const fill = (id) => find(vessel(id), (n) => n.classList.contains('level-fill'));
  assert.equal(fill('pressurizer').getAttribute('height'), '48');
  assert.equal(fill('sg-a').getAttribute('height'), '40');
  assert.equal(fill('sg-b').getAttribute('height'), '40');
  const rods = findAll(vessel('reactor-vessel'), (n) => n.classList.contains('rod-bank'));
  assert.equal(rods.length, 3);
  assert.ok(rods.every((n) => n.getAttribute('height') === '40'));
  plant.readings.sg_level_a.value = 75;
  plant.readings.sg_level_a.stale = true;
  plant.readings.sg_level_b.value = null;
  plant.readings.rod_position.value = 100;
  render(root, plant);
  assert.equal(fill('sg-a').getAttribute('height'), '60');
  assert.ok(fill('sg-a').classList.contains('stale'));
  assert.equal(fill('sg-b').getAttribute('height'), '0');
  assert.ok(rods.every((n) => n.getAttribute('height') === '80'));
  assert.ok(vessel('pressurizer_relief').classList.contains('open'));
  assert.ok(!vessel('steam_relief').classList.contains('open'));
});

function pipeSegments(mimic) {
  return findAll(mimic, (n) => (n.classList.contains('pipe') || n.classList.contains('shaft'))).map((node) => {
    const bridge = node.tagName === 'path';
    const values = bridge ? node.getAttribute('d').match(/-?\d+(?:\.\d+)?/g).map(Number) : null;
    const [x1, y1, x2, y2] = bridge
      ? [values[0], values[1], values[4], values[5]]
      : ['x1', 'y1', 'x2', 'y2'].map((a) => +node.getAttribute(a));
    return { x1, y1, x2, y2, bridge, node,
      getAttribute: (a) => ({ x1, y1, x2, y2 })[a] };
  });
}

test('process routes clear all equipment, headings and boxes with at most four bridged crossings', (t) => {
  for (const state of [true, false, null, 'stale']) {
    const root = fakeRoot();
    const plant = structuredClone(SAMPLE);
    for (const id of Object.keys(plant.status)) plant.status[id] = state === 'stale' ? true : state;
    if (state === 'stale') for (const link of plant.links) link.online = false;
    render(root, plant);
    const mimic = find(root, (n) => n.classList.contains('mimic'));
    const lines = pipeSegments(mimic);
    const obstacles = findAll(mimic, (n) => n.getAttribute('data-bounds') || n.classList.contains('data-box') || n.tagName === 'text').map((n) => {
      const bounds = n.getAttribute('data-bounds');
      const [x, y, w, h] = bounds ? bounds.split(',').map(Number) : [];
      return { node: n, name: bounds ? n.getAttribute('data-equipment') : n.textContent || n.parentNode.textContent,
        box: bounds ? { x, y, w, h } : n.tagName === 'text' ? textRect(n) : {
          x: +n.getAttribute('x'), y: +n.getAttribute('y'), w: +n.getAttribute('width'), h: +n.getAttribute('height'),
        }, equipment: !!bounds };
    });
    const errors = [];
    let crossings = 0, overlapCount = 0, minimum = Infinity;
    const interior = (v, a, b) => v > Math.min(a, b) && v < Math.max(a, b);
    for (const [i, a] of lines.entries()) {
      assert.ok(a.x1 === a.x2 || a.y1 === a.y2, 'orthogonal pipe');
      assert.ok(a.x1 !== a.x2 || a.y1 !== a.y2, 'nonempty pipe');
      for (const o of obstacles) {
        const b = o.box;
        if (segmentHitsRect(a, b)) {
          const vertical = a.x1 === a.x2;
          const length = vertical
            ? Math.min(Math.max(a.y1, a.y2), b.y + b.h) - Math.max(Math.min(a.y1, a.y2), b.y)
            : Math.min(Math.max(a.x1, a.x2), b.x + b.w) - Math.max(Math.min(a.x1, a.x2), b.x);
          const endpoint = [[a.x1, a.y1], [a.x2, a.y2]].some(([x, y]) => x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h);
          if (!o.equipment || length !== 0 || !endpoint) errors.push(`Pipe ${a.x1},${a.y1} to ${a.x2},${a.y2} hits ${o.name}`);
        }
        const endpoint = [[a.x1, a.y1], [a.x2, a.y2]].some(([x, y]) =>
          x >= b.x && x <= b.x + b.w && y >= b.y && y <= b.y + b.h);
        if (!(o.equipment && endpoint)) {
          const values = a.bridge ? a.node.getAttribute('d').match(/-?\d+(?:\.\d+)?/g).map(Number) : [a.x1, a.y1, a.x2, a.y2];
          const xs = values.filter((_, i) => i % 2 === 0), ys = values.filter((_, i) => i % 2 === 1);
          const dx = Math.max(b.x - Math.max(...xs), Math.min(...xs) - b.x - b.w, 0);
          const dy = Math.max(b.y - Math.max(...ys), Math.min(...ys) - b.y - b.h, 0);
          const stroke = a.node.classList.contains('primary-hot') ? 5 :
            a.node.classList.contains('primary-cold') || a.node.classList.contains('steam') ? 3 : 2;
          const border = o.equipment ? 0.75 : o.node.classList.contains('data-box') ? 0.5 : 0;
          for (const width of [1280, 1440]) {
            const clearance = (Math.hypot(dx, dy) - stroke / 2 - border) * (width - 58) / 1280;
            minimum = Math.min(minimum, clearance);
            if (clearance < 8) errors.push(`${width}px: ${a.x1},${a.y1} to ${a.x2},${a.y2} clears ${o.name} by ${clearance.toFixed(2)}px`);
          }
        }
        if (a.bridge) {
          const extent = a.node.getAttribute('d').match(/-?\d+(?:\.\d+)?/g).map(Number);
          const bridgeBox = { x: Math.min(extent[0], extent[2], extent[4]), y: Math.min(extent[1], extent[3], extent[5]),
            w: Math.max(extent[0], extent[2], extent[4]) - Math.min(extent[0], extent[2], extent[4]),
            h: Math.max(extent[1], extent[3], extent[5]) - Math.min(extent[1], extent[3], extent[5]) };
          if (overlaps(bridgeBox, b)) errors.push(`Bridge hits ${o.name}`);
        }
      }
      for (const b of lines.slice(i + 1)) {
        const av = a.x1 === a.x2, bv = b.x1 === b.x2;
        if (av === bv) {
          if ((av ? a.x1 === b.x1 : a.y1 === b.y1) &&
            Math.max(Math.min(av ? a.y1 : a.x1, av ? a.y2 : a.x2), Math.min(bv ? b.y1 : b.x1, bv ? b.y2 : b.x2)) <
            Math.min(Math.max(av ? a.y1 : a.x1, av ? a.y2 : a.x2), Math.max(bv ? b.y1 : b.x1, bv ? b.y2 : b.x2))) overlapCount++;
        } else {
          const v = av ? a : b, h = av ? b : a;
          if (interior(v.x1, h.x1, h.x2) && interior(h.y1, v.y1, v.y2)) {
            crossings++;
            if (!v.bridge && !h.bridge) errors.push(`Unbridged crossing at ${v.x1},${h.y1}`);
          }
        }
      }
    }
    for (const [i, a] of obstacles.entries()) {
      if (!a.node.classList.contains('data-box')) continue;
      for (const b of obstacles.slice(i + 1)) {
        if ((b.node.classList.contains('data-box') || b.equipment) && overlaps(a.box, b.box)) errors.push(`Box ${a.name} overlaps ${b.name}`);
      }
    }
    t.diagnostic(`${lines.length} segments; ${crossings} crossings; ${overlapCount} overlaps; minimum clearance ${minimum.toFixed(2)}px`);
    assert.deepEqual(errors, []);
    assert.equal(overlapCount, 0);
    assert.ok(crossings <= 4, `${crossings} crossings`);
  }
});

test('trends use at least five percent of each instrument scale and center steady data', () => {
  const root = fakeRoot();
  const spans = [
    ['neutron_power', 6, 100], ['pressurizer_pressure', 0.3, 15.5],
    ['hot_leg_a', 3.5, 325], ['steam_pressure', 0.5, 6.9],
    ['pressurizer_level', 5, 60], ['generator_output', 35, 900],
  ];
  for (const fraction of [0, 0.1, 1, 3]) {
    const history = Object.fromEntries(spans.map(([id, span, center]) => [id, { samples: [
      { time: '2026-03-14T07:43:12Z', value: center - span * fraction / 2 },
      { time: '2026-03-14T07:43:13Z', value: center + span * fraction / 2 },
    ] }]));
    render(root, SAMPLE, history);
    const lines = findAll(root, (n) => n.tagName === 'polyline');
    for (const [index, line] of lines.entries()) {
      const ys = line.getAttribute('points').split(' ').map((p) => +p.split(',')[1]);
      assert.ok(Math.abs((ys[0] + ys[1]) / 2 - 22) < 0.1, spans[index][0]);
      assert.ok(Math.abs(ys[0] - ys[1] - Math.min(fraction, 1) * 32) < 0.1, spans[index][0]);
    }
  }
  render(root, SAMPLE, { pressurizer_pressure: { samples: [
    { time: '2026-03-14T07:43:12Z', value: 15.46 },
    { time: '2026-03-14T07:43:13Z', value: 15.53 },
  ] } });
  const ys = findAll(root, (n) => n.tagName === 'polyline')[1].getAttribute('points').split(' ').map((p) => +p.split(',')[1]);
  assert.ok(ys[0] - ys[1] < 8, 'quantized pressure uses less than a quarter of the plot height');
});

test('one selected button stays marked beside its confirmation through polls and clears on every exit', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const root = fakeRoot();
  render(root, SAMPLE);
  const confirmation = byLabel(root, 'Selected action');
  const buttons = [byButton(root, 'Trip reactor'), byAria(root, 'Stop Coolant pump A'), byAria(root, 'Set Pressurizer pressure control to manual')];
  await withFetch({ status: 200 }, { ok: true }, async (calls) => {
    for (const btn of buttons) {
      await btn.listeners.get('click')[0]();
      assert.equal(btn.getAttribute('aria-pressed'), 'true');
      const group = btn.parentNode.classList.contains('control-group') ? btn.parentNode : btn.parentNode.parentNode;
      assert.equal(confirmation.parentNode, group);
      assert.equal(findAll(root, (n) => n.getAttribute('aria-pressed') === 'true').length, 1);
      assert.equal(findAll(root, (n) => n === confirmation).length, 1);
      render(root, SAMPLE);
      assert.equal(btn.getAttribute('aria-pressed'), 'true');
    }
    assert.equal(buttons[0].getAttribute('aria-pressed'), 'false');
    assert.equal(buttons[1].getAttribute('aria-pressed'), 'false');
    await byButton(root, 'Cancel').listeners.get('click')[0]();
    assert.equal(buttons[2].getAttribute('aria-pressed'), 'false');
    assert.deepEqual(calls, []);
    for (const btn of buttons) {
      await btn.listeners.get('click')[0]();
      t.mock.timers.tick(4999);
      assert.equal(btn.getAttribute('aria-pressed'), 'true');
      t.mock.timers.tick(1);
      assert.equal(btn.getAttribute('aria-pressed'), 'false');
      assert.equal(confirmation.getAttribute('hidden'), '');
      await btn.listeners.get('click')[0]();
      await byButton(root, 'Execute').listeners.get('click')[0]();
      assert.equal(btn.getAttribute('aria-pressed'), 'false');
      assert.equal(confirmation.getAttribute('hidden'), '');
    }
    assert.equal(calls.length, 3);
  });
});

test('controller faceplates show ISA tags, abbreviated modes and stale quality', () => {
  const root = fakeRoot();
  const tags = { pressurizer: 'PIC-455', feed_a: 'LIC-421A', feed_b: 'LIC-421B', steam_dump: 'PIC-434' };
  for (const [mode, word] of [['automatic', 'Auto'], ['manual', 'Man'], [null, 'No data']]) {
    const plant = structuredClone(SAMPLE);
    for (const id of Object.keys(tags)) plant.modes[id] = mode;
    render(root, plant);
    for (const [id, tag] of Object.entries(tags)) {
      const node = find(root, (n) => n.getAttribute('data-mode') === id);
      assert.equal(node.textContent, word);
      assert.ok(node.parentNode.textContent.startsWith(tag));
    }
    plant.links.forEach((link) => { link.online = false; });
    render(root, plant);
    for (const id of Object.keys(tags)) {
      const node = find(root, (n) => n.getAttribute('data-mode') === id);
      assert.equal(node.textContent, 'Stale');
      assert.ok(node.classList.contains('stale'));
    }
  }
});


test('graphic font metrics and confirmation sizing match the layout checks', () => {
  assert.match(styles, /\.mimic text\s*\{[^}]*font-family: ui-monospace, monospace;[^}]*font-size: 13px;/);
  assert.match(styles, /\.mimic \.instrument-value\s*\{[^}]*font-size: 15px;/);
  assert.match(styles, /\.confirmation\s*\{[^}]*flex-wrap: nowrap;/);
  assert.match(styles, /\.confirmation > button\s*\{[^}]*flex: none;[^}]*white-space: nowrap;/);
  assert.match(styles, /\.confirmation > \[role="status"\]\s*\{[^}]*min-width: 0;/);
});

test('cold legs descend to aligned pumps and take matching routes into the vessel', () => {
  const root = fakeRoot();
  render(root, SAMPLE);
  const mimic = find(root, (n) => n.classList.contains('mimic'));
  const lines = pipeSegments(mimic).filter((l) => l.node.classList.contains('primary-cold'));
  for (const [side, sgX, outlet, turn, inlet] of [['a', 270, 296, 490, 570], ['b', 870, 844, 710, 630]]) {
    const pump = find(mimic, (n) => n.getAttribute('data-equipment') === `coolant_pump_${side}`);
    const circle = find(pump, (n) => n.tagName === 'circle');
    assert.equal(+circle.getAttribute('cx'), sgX);
    assert.equal(+circle.getAttribute('cy'), 620);
    for (const segment of [[sgX, 500, sgX, 604], [outlet, 604, turn, 604], [turn, 604, turn, 500], [turn, 500, inlet, 500]]) {
      assert.equal(lines.filter((l) => [l.x1, l.y1, l.x2, l.y2].every((v, i) => v === segment[i])).length, 1);
    }
  }
  assert.equal(lines.filter((l) => Math.max(l.y1, l.y2) >= 400).length, 8);
});
