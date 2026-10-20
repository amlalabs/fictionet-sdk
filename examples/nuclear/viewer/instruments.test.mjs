import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  POINTS,
  findReading,
  formatGap,
  formatValue,
  instruments,
  isFrozen,
} from './instruments.mjs';

// Sensor tags in the order the plant lists them, and the serde value of each.
const SENSOR_ORDER = [
  'neutron_power',
  'rod_position',
  'hot_leg:a',
  'hot_leg:b',
  'cold_leg:a',
  'cold_leg:b',
  'pressurizer_pressure',
  'pressurizer_level',
  'coolant_flow:a',
  'coolant_flow:b',
  'steam_generator_level:a',
  'steam_generator_level:b',
  'steam_pressure',
  'steam_flow:a',
  'steam_flow:b',
  'feed_flow:a',
  'feed_flow:b',
  'turbine_valve',
  'generator_output',
  'condenser_pressure',
  'core_exit_temperature',
];

// Alarm variants in the order the plant lists them.
const ALARM_ORDER = [
  'pressurizer_pressure_high',
  'pressurizer_pressure_low',
  'pressurizer_level_high',
  'pressurizer_level_low',
  'hot_leg_temperature_high:a',
  'hot_leg_temperature_high:b',
  'steam_generator_level_low:a',
  'steam_generator_level_low:b',
  'steam_generator_level_high:a',
  'steam_generator_level_high:b',
  'feed_flow_low:a',
  'feed_flow_low:b',
  'coolant_flow_low:a',
  'coolant_flow_low:b',
  'condenser_vacuum_low',
  'feed_pump_tripped',
  'coolant_pump_tripped',
  'relief_valve_open',
  'reactor_tripped',
  'turbine_tripped',
  'neutron_power_high',
  'subcooling_margin_low',
];

/** A sensor or alarm tag in serde form: "hot_leg:b" is {"hot_leg":"b"}. */
function serde(tag) {
  const at = tag.indexOf(':');
  return at < 0 ? tag : { [tag.slice(0, at)]: tag.slice(at + 1) };
}

/** A plant at full power, in balance. */
function baseTruth() {
  return {
    reactor: {
      neutron_power_percent: 100.0,
      thermal_mw: 1800.0,
      decay_heat_percent: 0.0,
      reactivity_pcm: 0.0,
      control_rod_percent: 50.0,
      rod_demand_percent: 50.0,
      shutdown_rod_percent_inserted: 0.0,
      fuel_temperature_c: 1200.0,
      core_exit_c: 325.5,
      trip: null,
    },
    primary: {
      loops: [
        {
          hot_leg_c: 325.2,
          cold_leg_c: 292.4,
          steam_generator_primary_c: 310.0,
          flow_percent: 100.0,
          pump_running: true,
          pump_speed_percent: 100.0,
        },
        {
          hot_leg_c: 325.1,
          cold_leg_c: 292.3,
          steam_generator_primary_c: 310.0,
          flow_percent: 100.0,
          pump_running: true,
          pump_speed_percent: 100.0,
        },
      ],
      average_temperature_c: 308.8,
      pressure_mpa: 15.5,
      subcooling_margin_c: 19.8,
      level_percent: 55.0,
      heaters_on: false,
      heater_fraction: 0.0,
      spray_percent: 0.0,
      relief_open: false,
    },
    secondary: {
      loops: [
        {
          level_percent: 50.0,
          steam_kg_s: 400.0,
          feed_kg_s: 400.0,
          feed_valve_percent: 60.0,
          heat_transfer_mw: 900.0,
        },
        {
          level_percent: 50.0,
          steam_kg_s: 400.0,
          feed_kg_s: 400.0,
          feed_valve_percent: 60.0,
          heat_transfer_mw: 900.0,
        },
      ],
      steam_pressure_mpa: 6.9,
      feed_pumps_running: [true, true],
      auxiliary_feed_running: false,
      turbine_valve_percent: 90.0,
      turbine_tripped: false,
      generator_mw: 600.0,
      steam_dump_percent: 0.0,
      steam_relief_open: false,
      condenser_pressure_kpa: 5.0,
      circulating_water_running: true,
    },
    controllers: {
      feed_level: ['automatic', 'automatic'],
      pressurizer_pressure: 'automatic',
      steam_dump: 'automatic',
    },
  };
}

/** The true value of each instrument point, in the same order as SENSOR_ORDER. */
function trueValues(t) {
  return {
    neutron_power: t.reactor.neutron_power_percent,
    rod_position: t.reactor.control_rod_percent,
    'hot_leg:a': t.primary.loops[0].hot_leg_c,
    'hot_leg:b': t.primary.loops[1].hot_leg_c,
    'cold_leg:a': t.primary.loops[0].cold_leg_c,
    'cold_leg:b': t.primary.loops[1].cold_leg_c,
    pressurizer_pressure: t.primary.pressure_mpa,
    pressurizer_level: t.primary.level_percent,
    'coolant_flow:a': t.primary.loops[0].flow_percent,
    'coolant_flow:b': t.primary.loops[1].flow_percent,
    'steam_generator_level:a': t.secondary.loops[0].level_percent,
    'steam_generator_level:b': t.secondary.loops[1].level_percent,
    steam_pressure: t.secondary.steam_pressure_mpa,
    'steam_flow:a': t.secondary.loops[0].steam_kg_s,
    'steam_flow:b': t.secondary.loops[1].steam_kg_s,
    'feed_flow:a': t.secondary.loops[0].feed_kg_s,
    'feed_flow:b': t.secondary.loops[1].feed_kg_s,
    turbine_valve: t.secondary.turbine_valve_percent,
    generator_output: t.secondary.generator_mw,
    condenser_pressure: t.secondary.condenser_pressure_kpa,
    core_exit_temperature: t.reactor.core_exit_c,
  };
}

/**
 * A PlantSnapshot as the world serializes it. `edit` changes the true state,
 * `readings` overrides a sensor's reading (value and fault), and `alarms` lights
 * alarms by tag. Every other reading agrees with its true value.
 */
function snapshot({
  edit = () => {},
  readings = {},
  alarms = {},
  quiet = false,
  revision = 4,
} = {}) {
  const truth = baseTruth();
  edit(truth);
  const truths = trueValues(truth);
  const channels = SENSOR_ORDER.map((tag) => {
    const override = readings[tag] ?? {};
    return {
      sensor: serde(tag),
      reading: {
        value: override.value ?? truths[tag],
        sampled_at_ms: 250_000,
      },
      fault: override.fault ?? null,
    };
  });
  const alarmSlots = ALARM_ORDER.map((tag) =>
    alarms[tag] ? { alarm: serde(tag), state: alarms[tag] } : null,
  );
  const sensorFaults = SENSOR_ORDER.map((tag) => readings[tag]?.fault ?? null);
  return {
    at_ms: 250_000,
    revision,
    operator_actions: 1,
    model_limit: false,
    last_fault_start_ms: null,
    first_action_after_fault_ms: null,
    truth,
    readings: channels,
    reported_status: {
      coolant_pumps_running: [true, true],
      feed_pumps_running: [true, true],
      auxiliary_feed_running: false,
      circulating_water_running: true,
      pressurizer_heaters_on: false,
      pressurizer_relief_open: false,
      steam_relief_open: false,
      reactor_tripped: false,
      turbine_tripped: false,
    },
    telemetry: { quiet, heartbeat: 1234, last_sample_ms: 250_000 },
    alarms: alarmSlots,
    faults: {
      process: [null, null, null, null, null, null, null],
      sensors: sensorFaults,
      telemetry_quiet: quiet,
    },
  };
}

function pair(result, key) {
  const found = result.pairs.find((p) => p.key === key);
  assert.ok(found, `no pair for ${key}`);
  return found;
}

test('a normal snapshot has no diverged pair and no frozen reading', () => {
  // Reported values differ from true by instrument noise only.
  const noisy = Object.fromEntries(
    SENSOR_ORDER.map((tag) => [tag, { value: trueValues(baseTruth())[tag] + 0.03 }]),
  );
  const result = instruments(snapshot({ readings: noisy }));

  assert.equal(result.pairs.length, POINTS.length);
  assert.equal(result.pairs.length, 21);
  for (const p of result.pairs) {
    assert.equal(p.diverged, false, `${p.key} should agree with its true value`);
    assert.equal(p.frozen, false, `${p.key} should not be frozen`);
    assert.ok(Math.abs(p.gap) < 0.1, `${p.key} gap ${p.gap} should be noise`);
  }
  assert.deepEqual(result.alarms, []);
  assert.equal(result.telemetry.quiet, false);
});

test('a stuck hot leg B shows its gap from the true value and is diverged', () => {
  const snap = snapshot({
    // Loop B heats up while its hot-leg instrument holds at 325.0 C.
    edit: (t) => {
      t.primary.loops[1].hot_leg_c = 330.4;
    },
    readings: {
      'hot_leg:b': { value: 325.0, fault: { stuck: { value: 3250 } } },
    },
    alarms: { subcooling_margin_low: 'active' },
  });
  const result = instruments(snap);

  const hotB = pair(result, 'hot_leg:b');
  assert.equal(hotB.label, 'Hot leg B');
  assert.equal(hotB.trueValue, 330.4);
  assert.equal(hotB.reported, 325.0);
  assert.ok(Math.abs(hotB.gap - -5.4) < 1e-9, `gap ${hotB.gap}`);
  assert.equal(hotB.diverged, true);
  assert.equal(hotB.fault, 'stuck');
  assert.equal(hotB.frozen, false, 'a stuck instrument still samples');

  assert.equal(pair(result, 'hot_leg:a').diverged, false);
  assert.deepEqual(result.alarms, [
    { key: 'subcooling_margin_low', label: 'Subcooling margin low', state: 'active' },
  ]);
  assert.equal(findReading(snap, { hot_leg: 'b' }).fault.stuck.value, 3250);
});

test('a telemetry-quiet snapshot marks every reading frozen', () => {
  // The held hot-leg value stays at 325.0 C while the true loop B moves on.
  const snap = snapshot({
    quiet: true,
    edit: (t) => {
      t.primary.loops[1].hot_leg_c = 330.4;
    },
    readings: { 'hot_leg:b': { value: 325.0 } },
  });
  const result = instruments(snap);

  assert.equal(result.telemetry.quiet, true);
  assert.equal(result.pairs.length, 21);
  for (const p of result.pairs) {
    assert.equal(p.frozen, true, `${p.key} should be frozen`);
  }
  const hotB = pair(result, 'hot_leg:b');
  assert.equal(hotB.diverged, true, 'a frozen reading can still diverge from the plant');
  assert.equal(hotB.fault, null, 'the freeze comes from telemetry, not from the instrument');
});

test('a quiet sensor freezes only its own pair', () => {
  const snap = snapshot({
    readings: { 'cold_leg:a': { value: 292.4, fault: 'quiet' } },
  });
  const result = instruments(snap);

  assert.equal(pair(result, 'cold_leg:a').frozen, true);
  assert.equal(pair(result, 'cold_leg:a').fault, 'quiet');
  assert.equal(pair(result, 'cold_leg:b').frozen, false);
  assert.equal(isFrozen(snap, 'cold_leg:a'), true);
  assert.equal(isFrozen(snap, 'cold_leg:b'), false);
});

test('a small negative gap prints without a minus sign', () => {
  assert.equal(formatGap(-0.04, 'C'), '0.0 °C');
  assert.equal(formatGap(-5.4, 'C'), '-5.4 °C');
  assert.equal(formatGap(0.26, 'C'), '+0.3 °C');
  assert.equal(formatValue(325.0, 'C'), '325.0 °C');
  assert.equal(formatValue(15.5, 'MPa'), '15.50 MPa');
  assert.equal(formatValue(null, 'C'), 'no reading');
});
