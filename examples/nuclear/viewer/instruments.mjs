// Turns one plant snapshot (the JSON the nuclear world publishes) into the
// values the viewer shows.
//
// This module is pure: no Three.js, no DOM, no clock. Every number it returns
// comes from the snapshot it was given.
//
// Each displayed point has a true value from snapshot.truth. When an
// instrument feeds the point, it also has a reported value from the matching
// snapshot.readings entry. The gap is reported minus true. A reading is frozen
// when telemetry is quiet or its own instrument has a quiet fault.

const LOOPS = ['a', 'b'];

/**
 * Gap above which a pair counts as diverged, per unit. Instrument noise stays
 * well inside these limits; a stuck or biased instrument does not.
 */
export const DIVERGENCE = Object.freeze({
  '%': 1,
  C: 0.5,
  MPa: 0.05,
  kPa: 0.5,
  'kg/s': 1,
  MW: 5,
});

/** Decimal places shown for each unit. */
const DECIMALS = Object.freeze({ '%': 1, C: 1, MPa: 2, kPa: 1, 'kg/s': 1, MW: 1 });

/** How each unit is written on screen. */
const UNIT_TEXT = Object.freeze({
  '%': '%',
  C: '°C',
  MPa: 'MPa',
  kPa: 'kPa',
  'kg/s': 'kg/s',
  MW: 'MW',
});

const LOOP_NAME = (loop) => loop.toUpperCase();

/**
 * The displayed points, in the order the plant lists its instruments. `key` is
 * the sensor tag (`neutron_power`, `hot_leg:a`), `range` is the gauge scale for
 * the scene, `physical` marks scale ends at physical limits, and `truth` reads
 * the true value from snapshot.truth.
 */
export const POINTS = Object.freeze([
  point('neutron_power', 'Neutron power', '%', [0, 120], [true, false], (t) => t.reactor.neutron_power_percent),
  point('rod_position', 'Control rod position', '%', [0, 100], [true, true], (t) => t.reactor.control_rod_percent),
  ...loopPoints('hot_leg', 'Hot leg', 'C', [260, 350], [false, false], (t, i) => t.primary.loops[i].hot_leg_c),
  ...loopPoints('cold_leg', 'Cold leg', 'C', [260, 350], [false, false], (t, i) => t.primary.loops[i].cold_leg_c),
  point('pressurizer_pressure', 'Pressurizer pressure', 'MPa', [12, 18], [false, false], (t) => t.primary.pressure_mpa),
  point('pressurizer_level', 'Pressurizer level', '%', [0, 100], [true, false], (t) => t.primary.level_percent),
  ...loopPoints(
    'coolant_flow',
    'Coolant flow',
    '%',
    [0, 120],
    [true, false],
    (t, i) => t.primary.loops[i].flow_percent,
  ),
  ...loopPoints(
    'steam_generator_level',
    'Steam generator level',
    '%',
    [0, 100],
    [true, false],
    (t, i) => t.secondary.loops[i].level_percent,
  ),
  point('steam_pressure', 'Steam pressure', 'MPa', [0, 10], [true, false], (t) => t.secondary.steam_pressure_mpa),
  ...loopPoints(
    'steam_flow',
    'Steam flow',
    'kg/s',
    [0, 1000],
    [true, false],
    (t, i) => t.secondary.loops[i].steam_kg_s,
  ),
  ...loopPoints('feed_flow', 'Feed flow', 'kg/s', [0, 1000], [true, false], (t, i) => t.secondary.loops[i].feed_kg_s),
  point('turbine_valve', 'Turbine valve', '%', [0, 100], [true, true], (t) => t.secondary.turbine_valve_percent),
  point('generator_output', 'Generator output', 'MW', [0, 700], [true, false], (t) => t.secondary.generator_mw),
  point(
    'condenser_pressure',
    'Condenser pressure',
    'kPa',
    [0, 20],
    [true, false],
    (t) => t.secondary.condenser_pressure_kpa,
  ),
  point(
    'core_exit_temperature',
    'Core exit temperature',
    'C',
    [260, 350],
    [false, false],
    (t) => t.reactor.core_exit_c,
  ),
]);

function point(key, label, unit, range, physical, truth) {
  return { key, label, unit, range, physical, truth };
}

function loopPoints(key, label, unit, range, physical, truth) {
  return LOOPS.map((loop, i) =>
    point(`${key}:${loop}`, `${label} ${LOOP_NAME(loop)}`, unit, range, physical, (t) => truth(t, i)),
  );
}

const ALARM_NAMES = Object.freeze({
  pressurizer_pressure_high: 'Pressurizer pressure high',
  pressurizer_pressure_low: 'Pressurizer pressure low',
  pressurizer_level_high: 'Pressurizer level high',
  pressurizer_level_low: 'Pressurizer level low',
  hot_leg_temperature_high: 'Hot leg temperature high',
  steam_generator_level_low: 'Steam generator level low',
  steam_generator_level_high: 'Steam generator level high',
  feed_flow_low: 'Feed flow low',
  coolant_flow_low: 'Coolant flow low',
  condenser_vacuum_low: 'Condenser vacuum low',
  feed_pump_tripped: 'Feed pump tripped',
  coolant_pump_tripped: 'Coolant pump tripped',
  relief_valve_open: 'Relief valve open',
  reactor_tripped: 'Reactor tripped',
  turbine_tripped: 'Turbine tripped',
  neutron_power_high: 'Neutron power high',
  subcooling_margin_low: 'Subcooling margin low',
});

const PROCESS_NAMES = Object.freeze({
  feed_pump_trip: 'Feed pump trip',
  coolant_pump_trip: 'Coolant pump trip',
  feed_valve_stuck: 'Feed valve stuck',
  condenser_cooling_loss: 'Condenser cooling loss',
});

const TRIP_NAMES = Object.freeze({
  manual: 'Manual trip',
  neutron_power_high: 'Neutron power high',
  pressurizer_pressure_high: 'Pressurizer pressure high',
  pressurizer_pressure_low: 'Pressurizer pressure low',
  coolant_flow_low: 'Coolant flow low',
  steam_generator_level_low: 'Steam generator level low',
  hot_leg_temperature_high: 'Hot leg temperature high',
  turbine_trip: 'Turbine trip',
});

/**
 * A serde tag as a string. A unit variant is its name ("manual"); a newtype
 * variant is its name and its value joined by a colon ("hot_leg:a"); a struct
 * variant joins its field values the same way ("feed_valve_stuck:b").
 */
export function tagKey(value) {
  if (typeof value === 'string') return value;
  const [name, inner] = Object.entries(value)[0];
  if (inner === null || typeof inner !== 'object') return `${name}:${inner}`;
  return `${name}:${Object.values(inner).join(':')}`;
}

/** The sensor tag of a snapshot channel or of a sensor value, as in POINTS. */
export function sensorKey(sensor) {
  return tagKey(sensor);
}

/**
 * The reading channel for a sensor, or null. Takes a sensor tag ("hot_leg:b")
 * or a sensor value from the snapshot.
 */
export function findReading(snapshot, sensor) {
  const key = typeof sensor === 'string' ? sensor : sensorKey(sensor);
  return snapshot.readings.find((channel) => sensorKey(channel.sensor) === key) ?? null;
}

/** The fault kind of a reading: "quiet", "stuck", "bias", or null when clean. */
export function faultKind(fault) {
  if (fault === null || fault === undefined) return null;
  return typeof fault === 'string' ? fault : Object.keys(fault)[0];
}

/** True when a point's reported value is held, not sampled. */
export function isFrozen(snapshot, sensor) {
  if (snapshot.telemetry.quiet === true) return true;
  const channel = findReading(snapshot, sensor);
  return channel !== null && faultKind(channel.fault) === 'quiet';
}

/** The plain-words name of an alarm, with its loop when it has one. */
export function alarmLabel(alarm) {
  const [name, loop] = tagKey(alarm).split(':');
  const base = ALARM_NAMES[name] ?? name;
  return loop ? `${base}, loop ${LOOP_NAME(loop)}` : base;
}

/** The plain-words name of a process fault, with its pump or line when it has one. */
export function processLabel(fault) {
  const [name, loop] = tagKey(fault).split(':');
  const base = PROCESS_NAMES[name] ?? name;
  return loop ? `${base}, loop ${LOOP_NAME(loop)}` : base;
}

/** The plain-words cause of a reactor trip. */
export function tripLabel(cause) {
  const [name, loop] = tagKey(cause).split(':');
  const base = TRIP_NAMES[name] ?? name;
  return loop ? `${base}, loop ${LOOP_NAME(loop)}` : base;
}

/** A value with its unit, for display: "325.0 °C", "15.50 MPa", "48.0%". */
export function formatValue(value, unit) {
  if (value === null || value === undefined) return 'no reading';
  const text = value.toFixed(DECIMALS[unit] ?? 1);
  return unit === '%' ? `${text}%` : `${text} ${UNIT_TEXT[unit] ?? unit}`;
}

/** A signed gap for display. A gap that rounds to zero prints without a sign. */
export function formatGap(gap, unit) {
  if (gap === null || gap === undefined) return 'no gap';
  const decimals = DECIMALS[unit] ?? 1;
  const rounded = Number(gap.toFixed(decimals));
  const sign = rounded > 0 ? '+' : '';
  return `${sign}${rounded.toFixed(decimals)}${unit === '%' ? '%' : ` ${UNIT_TEXT[unit] ?? unit}`}`;
}

/**
 * The viewer's reading of one snapshot.
 *
 * `pairs` has one entry per displayed point, in POINTS order. Each pair holds
 * the true value, the reported value (null when no instrument feeds the point),
 * the gap, the diverged, frozen and marked flags, and the fault kind. `marked`
 * is a diverged pair whose gap comes from a fault or a freeze. The other
 * sections hold the true values the 3D scene moves things with, and the alarms
 * with their states.
 */
export function instruments(snapshot) {
  const quiet = snapshot.telemetry.quiet === true;
  const pairs = POINTS.map((p) => {
    const channel = findReading(snapshot, p.key);
    const trueValue = p.truth(snapshot.truth);
    const reported = channel ? channel.reading.value : null;
    const gap = reported === null ? null : reported - trueValue;
    const fault = channel ? faultKind(channel.fault) : null;
    const diverged = gap !== null && Math.abs(gap) > DIVERGENCE[p.unit];
    const frozen = quiet || fault === 'quiet';
    return {
      key: p.key,
      label: p.label,
      unit: p.unit,
      range: p.range,
      trueValue,
      reported,
      gap,
      diverged,
      frozen,
      fault,
      // A gap from an instrument fault or a freeze is marked for the viewer.
      // A gap with no fault is lag: temperature readings trail fast changes.
      marked: diverged && (fault !== null || frozen),
      sampledAtMs: channel ? channel.reading.sampled_at_ms : null,
    };
  });

  const t = snapshot.truth;
  const rs = snapshot.reported_status;
  const trip = t.reactor.trip ?? null;

  return {
    atMs: snapshot.at_ms,
    revision: snapshot.revision,
    operatorActions: snapshot.operator_actions,
    modelLimit: snapshot.model_limit === true,
    lastFaultStartMs: snapshot.last_fault_start_ms ?? null,
    firstActionAfterFaultMs: snapshot.first_action_after_fault_ms ?? null,
    telemetry: {
      quiet,
      heartbeat: snapshot.telemetry.heartbeat,
      lastSampleMs: snapshot.telemetry.last_sample_ms,
    },
    pairs,
    alarms: snapshot.alarms
      .filter((entry) => entry !== null)
      .map((entry) => ({
        key: tagKey(entry.alarm),
        label: alarmLabel(entry.alarm),
        state: entry.state,
      })),
    processFaults: snapshot.faults.process
      .filter((fault) => fault !== null)
      .map((fault) => ({ key: tagKey(fault), label: processLabel(fault) })),
    reportedStatus: {
      coolantPumpsRunning: rs.coolant_pumps_running,
      feedPumpsRunning: rs.feed_pumps_running,
      auxiliaryFeedRunning: rs.auxiliary_feed_running,
      circulatingWaterRunning: rs.circulating_water_running,
      pressurizerHeatersOn: rs.pressurizer_heaters_on,
      pressurizerReliefOpen: rs.pressurizer_relief_open,
      steamReliefOpen: rs.steam_relief_open,
      reactorTripped: rs.reactor_tripped,
      turbineTripped: rs.turbine_tripped,
    },
    reactor: {
      tripped: trip !== null,
      tripCause: trip ? tripLabel(trip.cause) : null,
      neutronPowerPercent: t.reactor.neutron_power_percent,
      controlRodWithdrawnPercent: t.reactor.control_rod_percent,
      rodDemandPercent: t.reactor.rod_demand_percent,
      shutdownRodInsertedPercent: t.reactor.shutdown_rod_percent_inserted,
      coreExitC: t.reactor.core_exit_c,
      reactivityPcm: t.reactor.reactivity_pcm,
    },
    loops: t.primary.loops.map((loop, i) => ({
      id: LOOPS[i],
      hotLegC: loop.hot_leg_c,
      coldLegC: loop.cold_leg_c,
      flowPercent: loop.flow_percent,
      pumpRunning: loop.pump_running,
      pumpSpeedPercent: loop.pump_speed_percent,
      steamGeneratorLevelPercent: t.secondary.loops[i].level_percent,
      steamKgS: t.secondary.loops[i].steam_kg_s,
      feedKgS: t.secondary.loops[i].feed_kg_s,
      feedValvePercent: t.secondary.loops[i].feed_valve_percent,
      feedPumpRunning: t.secondary.feed_pumps_running[i],
    })),
    pressurizer: {
      pressureMpa: t.primary.pressure_mpa,
      levelPercent: t.primary.level_percent,
      heatersOn: t.primary.heaters_on,
      sprayPercent: t.primary.spray_percent,
      reliefOpen: t.primary.relief_open,
    },
    secondary: {
      steamPressureMpa: t.secondary.steam_pressure_mpa,
      turbineValvePercent: t.secondary.turbine_valve_percent,
      turbineTripped: t.secondary.turbine_tripped,
      generatorMw: t.secondary.generator_mw,
      condenserPressureKpa: t.secondary.condenser_pressure_kpa,
      circulatingWaterRunning: t.secondary.circulating_water_running,
      steamDumpPercent: t.secondary.steam_dump_percent,
      steamReliefOpen: t.secondary.steam_relief_open,
      auxiliaryFeedRunning: t.secondary.auxiliary_feed_running,
    },
  };
}
