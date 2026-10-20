import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  FAULT_SENSORS,
  sensorCount,
  sensorFault,
  activeFaults,
  DIAL_SWEEP_DEG,
  ROTARY_SWEEP_DEG,
  advanceButton,
  advanceSwitch,
  coastDial,
  coverState,
  createButton,
  createDial,
  createRotary,
  createSwitch,
  dialValue,
  faultCommand,
  fault,
  outcomeOf,
  plant,
  postCommand,
  pressButton,
  pressCover,
  releaseButton,
  releaseDial,
  releaseRotary,
  resolveDetent,
  rotaryValue,
  setDial,
  settleDial,
  switchStop,
  switchAtRest,
  throwSwitch,
  toggleSwitch,
  turnDial,
  turnRotary,
} from './knobs.mjs';

const TENTHS = [0, 250, 500, 750, 1000];

test('the first covered press opens the guard without a command', () => {
  const closed = coverState();
  const opened = pressCover(closed);
  assert.deepEqual(closed, { open: false, fired: false });
  assert.deepEqual(opened, { state: { open: true, fired: false }, command: null });
});

test('an open guard sends one manual trip until it closes', () => {
  const opened = pressCover(coverState());
  const pressed = pressCover(opened.state);
  assert.equal(pressed.command, plant.manualTrip());
  assert.deepEqual(pressed.state, { open: true, fired: true });
  assert.equal(pressCover(pressed.state).command, null);
  const reopened = pressCover(coverState());
  assert.equal(reopened.command, null);
  assert.equal(pressCover(reopened.state).command, plant.manualTrip());
});

test('control lamps contrast with unlit lenses in light and both dark palettes', () => {
  const controls = readFileSync(new URL('./control-room.css', import.meta.url), 'utf8');
  const viewer = readFileSync(new URL('./viewer.css', import.meta.url), 'utf8');
  const green = [...controls.matchAll(/--control-green:\s*(#[\da-f]+);/g)].map(match => match[1]);
  const red = [...viewer.matchAll(/--accent:\s*(#[\da-f]+);/g)].map(match => match[1]);
  const off = [...viewer.matchAll(/--lamp-off:\s*(#[\da-f]+);/g)].map(match => match[1]);
  const luminance = hex => hex.slice(1).match(/../g).map(value => parseInt(value, 16) / 255)
    .map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
    .reduce((sum, value, i) => sum + value * [0.2126, 0.7152, 0.0722][i], 0);
  assert.equal(green.length, 3);
  assert.equal(red.length, 3);
  assert.equal(off.length, 3);
  for (let i = 0; i < 3; i++) {
    for (const lit of [green[i], red[i]]) {
      assert.ok((luminance(lit) + 0.05) / (luminance(off[i]) + 0.05) >= 3);
    }
  }
  assert.match(controls, /@media \(forced-colors: active\)[\s\S]*--control-green: Highlight;/);
});

test('a rotary with detents snaps to the nearest detent', () => {
  // Five detents over 240 degrees sit at 0, 60, 120, 180 and 240 degrees.
  assert.equal(resolveDetent(100, TENTHS, ROTARY_SWEEP_DEG).value, 500); // nearer 120
  assert.equal(resolveDetent(85, TENTHS, ROTARY_SWEEP_DEG).value, 250); // nearer 60
  assert.equal(resolveDetent(170, TENTHS, ROTARY_SWEEP_DEG).value, 750); // nearer 180
  assert.equal(resolveDetent(235, TENTHS, ROTARY_SWEEP_DEG).value, 1000); // nearer 240
  // A halfway angle goes to the lower detent.
  assert.equal(resolveDetent(90, TENTHS, ROTARY_SWEEP_DEG).value, 250);
  // A hand past an end detent still resolves to that end.
  assert.equal(resolveDetent(-6, TENTHS, ROTARY_SWEEP_DEG).value, 0);
  assert.equal(resolveDetent(250, TENTHS, ROTARY_SWEEP_DEG).value, 1000);

  // Releasing the hand between detents leaves the rotary on the nearest one.
  const rotary = turnRotary(createRotary(TENTHS, 0), 100);
  const released = releaseRotary(rotary);
  assert.equal(rotaryValue(released), 500);
  assert.equal(released.angle, 120);
});

test('a fast turn of the dial coasts, then settles within its range', () => {
  let dial = setDial(createDial({ min: 0, max: 1000, step: 1 }), 300);
  dial = releaseDial(dial, 400); // degrees per second, the way a flick arrives
  const start = dial.angle;
  let previous = dial.velocity;
  let frames = 0;
  while (dial.velocity !== 0 && frames < 600) {
    dial = coastDial(dial, 1 / 60);
    assert.ok(Math.abs(dial.velocity) <= Math.abs(previous), 'speed never rises while coasting');
    previous = dial.velocity;
    frames += 1;
  }
  assert.equal(dial.velocity, 0, 'the dial comes to rest');
  assert.ok(frames < 600, 'it settles in a bounded number of frames');
  assert.ok(dial.angle > start, 'it kept turning after release');
  assert.ok(dial.angle >= 0 && dial.angle <= DIAL_SWEEP_DEG, 'the final angle stays within the stops');
  const value = dialValue(dial);
  assert.ok(value >= 0 && value <= 1000, 'the final value stays within the range');

  // Once settled, more time changes nothing.
  assert.deepEqual(coastDial(dial, 5), dial);
});

test('a flick at full speed stops on the end stop and never passes it', () => {
  let dial = setDial(createDial({ min: 0, max: 1000, step: 1 }), 900);
  dial = releaseDial(dial, 1440);
  for (let i = 0; i < 600 && dial.velocity !== 0; i++) dial = coastDial(dial, 1 / 60);
  assert.equal(dial.velocity, 0);
  assert.equal(dial.angle, DIAL_SWEEP_DEG);
  assert.equal(dialValue(dial), 1000);
});

test('the settled coast matches the stepped coast', () => {
  const dial = releaseDial(setDial(createDial({ min: 0, max: 1000, step: 1 }), 200), 200);
  let stepped = dial;
  for (let i = 0; i < 1200 && stepped.velocity !== 0; i++) stepped = coastDial(stepped, 1 / 240);
  const settled = settleDial(dial);
  assert.equal(settled.velocity, 0);
  assert.ok(Math.abs(settled.angle - stepped.angle) < 0.05, `${settled.angle} vs ${stepped.angle}`);
});

test('a switch throws between its two firm stops', () => {
  let sw = createSwitch(false);
  assert.equal(switchStop(sw), 'off');
  assert.ok(switchAtRest(sw));

  sw = toggleSwitch(sw); // throw toward on
  assert.equal(switchStop(sw), 'on', 'toggling from off returns the on stop');
  assert.equal(switchAtRest(sw), false, 'it is still in travel');
  sw = advanceSwitch(sw, 0.1);
  assert.ok(sw.travel > 0 && sw.travel < 1, 'travel is partway');
  sw = advanceSwitch(sw, 10);
  assert.equal(sw.travel, 1, 'it stops exactly on the on stop');
  assert.ok(switchAtRest(sw));

  sw = toggleSwitch(sw); // throw back
  assert.equal(switchStop(sw), 'off', 'toggling from on returns the off stop');
  sw = advanceSwitch(sw, 10);
  assert.equal(sw.travel, 0, 'it stops exactly on the off stop');

  // A long step never moves a switch past a stop.
  assert.equal(advanceSwitch(throwSwitch(createSwitch(true), false), 99).travel, 0);
});

test('a posted command carries the revision of the snapshot it was made from', () => {
  const snapshot = { revision: 42, at_ms: 9000 };
  const change = fault.telemetryQuiet(true);
  const command = faultCommand(snapshot, change);
  assert.equal(command.expected_revision, 42);
  assert.deepEqual(command.change, { inject: 'telemetry_quiet' });

  const sent = [];
  const transport = {
    post(path, body) {
      sent.push({ path, body });
      return Promise.resolve({ status: 'applied', request_id: body.request_id, reply: { Ok: { revision: 43, at_ms: 9000 } } });
    },
  };
  return postCommand(transport, '/api/faults/command', command, { requestId: 'req-1' }).then((outcome) => {
    assert.equal(outcome.state, 'applied');
    assert.equal(sent.length, 1);
    assert.equal(sent[0].path, '/api/faults/command');
    assert.equal(sent[0].body.request_id, 'req-1');
    assert.equal(sent[0].body.command.expected_revision, 42);
    assert.deepEqual(sent[0].body.command.change, { inject: 'telemetry_quiet' });
  });
});

test('a dial sends the exact value it shows, in whole tenths', () => {
  const dial = setDial(createDial({ min: 0, max: 1000, step: 1 }), 480);
  assert.equal(dialValue(dial), 480);
  // A turn that stops between two steps still sends a whole step.
  const turned = turnDial(dial, 0.4);
  assert.equal(Number.isInteger(dialValue(turned)), true);
  assert.deepEqual(plant.rodDemand(dialValue(setDial(createDial({ min: 0, max: 1000, step: 1 }), 480))), {
    rod_demand: { tenths_percent: 480 },
  });
  assert.throws(() => plant.rodDemand(1001), RangeError);
  assert.throws(() => plant.rodDemand(12.5), RangeError);
});

test('a pushbutton depresses and springs back', () => {
  let button = pressButton(createButton());
  button = advanceButton(button, 1);
  assert.equal(button.depth, 1, 'it bottoms out while held');
  button = releaseButton(button);
  button = advanceButton(button, 0.05);
  assert.ok(button.depth > 0 && button.depth < 1, 'it is partway back');
  button = advanceButton(button, 1);
  assert.equal(button.depth, 0, 'it springs fully back');
});

test('outcomes name the reply: applied, refused, pending, no reply, failed', () => {
  assert.equal(outcomeOf({ status: 'applied', reply: { Ok: { revision: 1, at_ms: 0 } } }).state, 'applied');
  assert.equal(outcomeOf({ status: 'pending' }).state, 'pending');

  const refused = outcomeOf({ status: 'applied', reply: { Err: { reason: 'tripped', revision: 3 } } });
  assert.equal(refused.state, 'refused');
  assert.match(refused.text, /reactor has tripped/);

  const rejected = outcomeOf({ status: 'rejected', rejection: { reason: 'stale_revision', current: 9 } });
  assert.equal(rejected.state, 'refused');
  assert.match(rejected.text, /changed/);

  assert.equal(outcomeOf({ status: 'timeout' }).state, 'no-reply');
  assert.equal(outcomeOf(null).state, 'failed');
});

test('a refused post reads the 409 body and a timeout reads the 504 body', async () => {
  const refuse = {
    post() {
      const error = new Error('409');
      error.body = { status: 'rejected', request_id: 'x', rejection: { reason: 'stale_revision', current: 10 } };
      return Promise.reject(error);
    },
  };
  const refusal = await postCommand(refuse, '/api/faults/command', faultCommand({ revision: 9 }, fault.clearAll()));
  assert.equal(refusal.state, 'refused');

  const late = {
    post() {
      const error = new Error('504');
      error.body = { status: 'timeout', request_id: 'x', error: 'no reply' };
      return Promise.reject(error);
    },
  };
  const timeout = await postCommand(late, '/api/plant/command', plant.manualTrip());
  assert.equal(timeout.state, 'no-reply');
});

test('the plant commands take the serde forms of the world', () => {
  assert.equal(plant.manualTrip(), 'manual_trip');
  assert.equal(plant.resetTrip(), 'reset_trip');
  assert.deepEqual(plant.pump({ coolant: 'b' }, false), { pump: { pump: { coolant: 'b' }, running: false } });
  assert.deepEqual(plant.valveDemand('turbine', 750), { valve_demand: { valve: 'turbine', permille: 750 } });
  assert.deepEqual(plant.controller({ feed_level: 'a' }, 'manual'), {
    controller: { controller: { feed_level: 'a' }, mode: 'manual' },
  });
  assert.deepEqual(fault.clearAll(), 'clear_all');
  assert.deepEqual(fault.stuckHotLeg('b', 3250, true), {
    inject: { sensor: { sensor: { hot_leg: 'b' }, kind: { stuck: { value: 3250 } } } },
  });
  assert.deepEqual(fault.stuckHotLeg('b', 3250, false), { clear: { sensor: { hot_leg: 'b' } } });
});

test('the sensor table follows every Rust sensor and its resolution', () => {
  const rust = readFileSync(new URL('../world/src/sensors.rs', import.meta.url), 'utf8');
  const all = rust.match(/pub const ALL:[\s\S]*?= \[([\s\S]*?)\];/)[1];
  const snake = name => name.replace(/[A-Z]/g, (letter, index) => `${index ? '_' : ''}${letter.toLowerCase()}`);
  const variants = [...all.matchAll(/Self::(\w+)(?:\(Loop::([AB])\))?/g)];
  const keys = variants.map(([, name, loop]) => loop ? `${snake(name)}:${loop.toLowerCase()}` : snake(name));
  assert.equal(keys.length, 22);
  assert.deepEqual(FAULT_SENSORS.map(point => point.key), keys);
  const spec = rust.match(/let \(unit, min, max, resolution\) = match self \{([\s\S]*?)\n        \};/)[1];
  const arms = [...spec.matchAll(/^\s*((?:Self::\w+(?:\(_\))?\s*(?:\|\s*)?)+|_)\s*=>\s*\{?\s*\(Unit::\w+,\s*[\d.]+,\s*[\d.]+,\s*([\d.]+)\)/gm)];
  assert.ok(arms.length > 0);
  variants.forEach(([, name, loop], index) => {
    const arm = arms.find(([, pattern]) => pattern.includes(`Self::${name}`)) ?? arms.find(([, pattern]) => pattern.trim() === '_');
    assert.ok(arm, name);
    const point = FAULT_SENSORS[index];
    assert.equal(point.resolution, Number(arm[2]), point.key);
    const sensor = loop ? { [snake(name)]: loop.toLowerCase() } : snake(name);
    assert.deepEqual(point.sensor, sensor);
  });
});

const faultSnapshot = () => ({
  revision: 72,
  readings: [],
  faults: { process: [], sensors: Array(22).fill(null), telemetry_quiet: false },
  truth: {
    reactor: { neutron_power_percent: 80, control_rod_percent: 60, core_exit_c: 330, shutdown_rod_percent_inserted: 20 },
    primary: { pressure_mpa: 15.5, level_percent: 50,
      loops: [{ hot_leg_c: 320, cold_leg_c: 280, flow_percent: 95 }, { hot_leg_c: 321, cold_leg_c: 281, flow_percent: 96 }] },
    secondary: { steam_pressure_mpa: 6.5, turbine_valve_percent: 70, generator_mw: 500, condenser_pressure_kpa: 5,
      loops: [{ level_percent: 55, steam_kg_s: 450, feed_kg_s: 440 }, { level_percent: 56, steam_kg_s: 451, feed_kg_s: 441 }] },
  },
});

function assertFaultCommand(snapshot, change, expected) {
  for (const revision of [snapshot.revision, snapshot.revision + 1]) {
    assert.deepEqual(faultCommand({ ...snapshot, revision }, change), { expected_revision: revision, change: expected });
  }
}

test('every sensor supports reported stuck counts, quiet and clearing with the current revision', () => {
  const snapshot = faultSnapshot();
  for (const point of FAULT_SENSORS) {
    snapshot.readings = [{ sensor: point.sensor, reading: { value: 12.34, sampled_at_ms: 250 } }];
    const stuck = sensorFault(snapshot, point, 'stuck');
    const count = point.resolution === 0.01 ? 1234 : 123;
    assertFaultCommand(snapshot, stuck.change, { inject: { sensor: { sensor: point.sensor, kind: { stuck: { value: count } } } } });
    assert.equal(stuck.note, 'Used the current reported reading.');
    assertFaultCommand(snapshot, sensorFault(snapshot, point, 'quiet').change,
      { inject: { sensor: { sensor: point.sensor, kind: 'quiet' } } });
    assertFaultCommand(snapshot, fault.clear({ sensor: point.sensor }), { clear: { sensor: point.sensor } });
  }
});

test('stuck falls back to truth only when the reported reading is absent', () => {
  const snapshot = faultSnapshot();
  const expected = [800, 600, 3200, 3210, 2800, 2810, 1550, 500, 950, 960, 550, 560, 650, 4500, 4510, 4400, 4410, 700, 5000, 50, 3300, 200];
  FAULT_SENSORS.forEach((point, index) => {
    const result = sensorFault(snapshot, point, 'stuck');
    assertFaultCommand(snapshot, result.change, { inject: { sensor: { sensor: point.sensor, kind: { stuck: { value: expected[index] } } } } });
    assert.match(result.note, /No reported reading. Used the true value/);
  });
  const point = FAULT_SENSORS[3];
  snapshot.readings = [{ sensor: point.sensor, reading: { value: 0 } }];
  assert.equal(sensorFault(snapshot, point, 'stuck').change.inject.sensor.kind.stuck.value, 0);
  snapshot.readings[0].reading.value = NaN;
  assert.throws(() => sensorFault(snapshot, point, 'stuck'), /finite/);
});

test('bias uses each point resolution and carries the snapshot revision', () => {
  const snapshot = faultSnapshot();
  for (const [key, value, delta] of [['hot_leg:b', -1.25, -13], ['pressurizer_pressure', 0.125, 13], ['feed_flow:a', 12, 120]]) {
    const point = FAULT_SENSORS.find(entry => entry.key === key);
    assertFaultCommand(snapshot, sensorFault(snapshot, point, 'bias', value).change,
      { inject: { sensor: { sensor: point.sensor, kind: { bias: { delta } } } } });
  }
});

test('signed counts round halves away from zero and refuse beyond the clamped limit', () => {
  for (const point of FAULT_SENSORS) {
    for (const [scaled, count] of [[1.5, 2], [-1.5, -2], [0.5, 1], [-0.5, -1], [0, 0], [32767, 32767], [-32768, -32768]]) {
      assert.equal(sensorCount(point, scaled * point.resolution), count);
    }
    for (const count of [32767.5, -32768.5, 40000, -40000]) {
      assert.throws(() => sensorCount(point, count * point.resolution), /Nearest limit/);
    }
    for (const value of [NaN, Infinity, -Infinity]) assert.throws(() => sensorCount(point, value), /finite/);
  }
});

test('process switches and telemetry encode injection and per-fault clearing', () => {
  const snapshot = faultSnapshot();
  const cases = [
    [on => fault.condenserCoolingLoss(on), { process: 'condenser_cooling_loss' }],
    [on => fault.telemetryQuiet(on), 'telemetry_quiet'],
  ];
  for (const loop of ['a', 'b']) {
    cases.push([on => fault.coolantPumpTrip(loop, on), { process: { coolant_pump_trip: { pump: loop } } }]);
    cases.push([on => fault.feedPumpTrip(loop, on), { process: { feed_pump_trip: { pump: loop } } }]);
  }
  for (const [build, target] of cases) {
    assertFaultCommand(snapshot, build(true), { inject: target });
    assertFaultCommand(snapshot, build(false), { clear: target });
  }
  assertFaultCommand(snapshot, fault.clearAll(), 'clear_all');
});

test('active faults name the point or equipment, kind and engineering value', () => {
  const snapshot = faultSnapshot();
  assert.deepEqual(activeFaults(snapshot), []);
  snapshot.faults.process = [null, { coolant_pump_trip: { pump: 'b' } }, { feed_pump_trip: { pump: 'a' } },
    { feed_valve_stuck: { line: 'b' } }, 'condenser_cooling_loss'];
  snapshot.faults.sensors[3] = { stuck: { value: 3236 } };
  snapshot.faults.sensors[6] = { bias: { delta: -12 } };
  snapshot.faults.sensors[15] = { bias: { delta: 120 } };
  snapshot.faults.sensors[21] = 'quiet';
  snapshot.faults.telemetry_quiet = true;
  const entries = activeFaults(snapshot);
  assert.deepEqual(entries.map(entry => entry.label), [
    'Coolant pump B: trip', 'Feed pump A: trip', 'Feed valve B: stuck', 'Condenser cooling: loss',
    'Hot leg B: stuck at 323.6 C', 'Pressurizer pressure: bias -0.12 MPa', 'Feed flow A: bias +12.0 kg/s',
    'Shutdown rod position: quiet', 'Telemetry: quiet',
  ]);
  const targets = [
    ...snapshot.faults.process.filter(Boolean).map(process => ({ process })),
    ...[3, 6, 15, 21].map(index => ({ sensor: FAULT_SENSORS[index].sensor })), 'telemetry_quiet',
  ];
  entries.forEach((entry, index) => assertFaultCommand(snapshot, entry.change, { clear: targets[index] }));
});

test('fault replies show stale, already active and inactive refusals', async () => {
  for (const [reason, message] of [
    ['stale_revision', /plant changed/],
    ['already_active', /already in effect/],
    ['not_active', /nothing to reset/],
  ]) {
    const transport = { post: async () => ({ status: 'applied', reply: { Err: { reason, revision: 73 } } }) };
    const outcome = await postCommand(transport, '/api/faults/command', faultCommand(faultSnapshot(), fault.clearAll()));
    assert.equal(outcome.state, 'refused');
    assert.match(outcome.text, message);
  }
});
