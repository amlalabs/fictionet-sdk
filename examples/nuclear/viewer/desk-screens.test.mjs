import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { instruments } from './instruments.mjs';
import { PALETTE_TOKENS } from './control-room.mjs';
import { paintDeskScreen, SCREEN_LAYOUTS, signature } from './desk-screens.mjs';

const palette = Object.fromEntries(
  ['surface', 'raised', 'sunken', 'ink', 'text', 'line', 'strongLine', 'steel', 'warning', 'accent', 'lampGlow'].map(
    (name) => [name, `palette:${name}`],
  ),
);
const points = [
  ['neutron_power', 'NI-41', 98.2, '%'],
  ['rod_position', 'ZT-401', 72.3, '%'],
  ['hot_leg:a', 'TE-411A', 322.5, 'C'],
  ['hot_leg:b', 'TE-411B', 323.6, 'C'],
  ['cold_leg:a', 'TE-412A', 291.2, 'C'],
  ['cold_leg:b', 'TE-412B', 292.3, 'C'],
  ['pressurizer_pressure', 'PT-455', 15.51, 'MPa'],
  ['pressurizer_level', 'LT-459', 51.2, '%'],
  ['coolant_flow:a', 'FT-414A', 98.7, '%'],
  ['coolant_flow:b', 'FT-414B', 99.8, '%'],
  ['steam_generator_level:a', 'LT-421A', 49.3, '%'],
  ['steam_generator_level:b', 'LT-421B', 50.4, '%'],
  ['steam_pressure', 'PT-431', 6.91, 'MPa'],
  ['steam_flow:a', 'FT-432A', 701.5, 'kg/s'],
  ['steam_flow:b', 'FT-432B', 702.6, 'kg/s'],
  ['feed_flow:a', 'FT-433A', 703.7, 'kg/s'],
  ['feed_flow:b', 'FT-433B', 704.8, 'kg/s'],
  ['turbine_valve', 'ZT-441', 95.9, '%'],
  ['generator_output', 'JT-451', 610.1, 'MW'],
  ['condenser_pressure', 'PT-452', 5.2, 'kPa'],
  ['core_exit_temperature', 'TE-413', 324.7, 'C'],
];
const alarmKeys = [
  'subcooling_margin_low',
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
  'coolant_flow_low:a',
  'coolant_flow_low:b',
  'condenser_vacuum_low',
  'neutron_power_high',
  'reactor_tripped',
  'turbine_tripped',
  'coolant_pump_tripped',
  'feed_pump_tripped',
  'relief_valve_open',
];

function viewFixture() {
  return {
    pairs: points.map(([key, tag, reported, unit]) => ({
      key,
      reported,
      unit,
      trueValue: 330,
      frozen: false,
      sampledAtMs: 1000,
    })),
    telemetry: { quiet: false, heartbeat: 42, lastSampleMs: 1000 },
    reportedStatus: {
      coolantPumpsRunning: [true, true],
      feedPumpsRunning: [true, true],
      reactorTripped: false,
      turbineTripped: false,
      pressurizerHeatersOn: true,
      pressurizerReliefOpen: false,
      steamReliefOpen: false,
      auxiliaryFeedRunning: false,
      circulatingWaterRunning: true,
    },
    alarms: alarmKeys.map((key) => ({ key, state: 'normal' })),
    atMs: 1000,
  };
}

function context() {
  const calls = [];
  const ctx = { calls };
  for (const name of [
    'save',
    'restore',
    'scale',
    'beginPath',
    'closePath',
    'moveTo',
    'lineTo',
    'arc',
    'roundRect',
    'quadraticCurveTo',
    'fill',
    'stroke',
    'fillRect',
    'strokeRect',
    'fillText',
  ]) {
    ctx[name] = (...args) => calls.push({ name, args, fill: ctx.fillStyle, stroke: ctx.strokeStyle, font: ctx.font });
  }
  return ctx;
}

function paint(view, layout) {
  const ctx = context();
  paintDeskScreen(ctx, { width: 1024, height: 512, view, palette, layout });
  return ctx.calls;
}

function texts(calls) {
  return calls.filter((call) => call.name === 'fillText').map((call) => call.args[0]);
}

test('overview screens show every HMI tag beside its reported value and unit at readable sizes', () => {
  const calls = SCREEN_LAYOUTS.slice(0, 2).flatMap((layout) => paint(viewFixture(), layout));
  const labels = calls.filter((call) => call.name === 'fillText');
  for (const [key, tag, value, unit] of points) {
    const i = labels.findIndex((call) => call.args[0] === tag);
    assert.ok(i >= 0, key);
    assert.ok(parseInt(labels[i].font) >= 18);
    assert.equal(labels[i + 1].args[0], `${value.toFixed(unit === 'MPa' ? 2 : 1)} ${unit}`);
    assert.ok(parseInt(labels[i + 1].font) >= 26);
  }
});

test('stuck hot leg uses the reported number and never reads plant truth', () => {
  const view = viewFixture();
  const hot = view.pairs.find((pair) => pair.key === 'hot_leg:b');
  hot.fault = 'stuck';
  hot.trueValue = 330;
  let output = texts(paint(view, 'primary'));
  assert.ok(output.includes('323.6 C'));
  assert.ok(!output.some((text) => text.includes('330')));
  for (const pair of view.pairs) {
    Object.defineProperty(pair, 'trueValue', {
      get() {
        throw new Error('Plant truth was read');
      },
    });
  }
  for (const key of ['truth', 'reactor', 'loops', 'pressurizer', 'secondary']) {
    Object.defineProperty(view, key, {
      get() {
        throw new Error('Plant truth was read');
      },
    });
  }
  for (const layout of SCREEN_LAYOUTS) {
    paint(view, layout);
    signature(view, layout);
  }
});

test('quiet telemetry displays held readings and the unchanged supplied heartbeat', () => {
  const view = viewFixture();
  view.telemetry.quiet = true;
  view.pairs.forEach((pair) => {
    pair.frozen = true;
  });
  const before = SCREEN_LAYOUTS.map((layout) => paint(view, layout));
  const signatures = SCREEN_LAYOUTS.map((layout) => signature(view, layout));
  view.atMs = 90000;
  view.pairs.forEach((pair) => {
    pair.trueValue += 80;
  });
  for (const [i, layout] of SCREEN_LAYOUTS.entries()) {
    const after = paint(view, layout);
    assert.deepEqual(after, before[i]);
    assert.equal(signature(view, layout), signatures[i]);
    assert.ok(texts(after).includes('Telemetry quiet · held · heartbeat 42'));
  }
  assert.ok(texts(before[0]).includes('323.6 C'));
});

test('normal equipment stays grey and stopped pumps and trips use warning colors', () => {
  const view = viewFixture();
  for (const layout of SCREEN_LAYOUTS) {
    assert.ok(paint(view, layout).every((call) => call.fill !== palette.warning && call.fill !== palette.lampGlow));
  }
  view.reportedStatus.coolantPumpsRunning[1] = false;
  view.reportedStatus.reactorTripped = true;
  view.reportedStatus.turbineTripped = true;
  view.reportedStatus.feedPumpsRunning[0] = false;
  for (const layout of SCREEN_LAYOUTS.slice(0, 2)) {
    const calls = paint(view, layout);
    assert.ok(calls.some((call) => call.name === 'fill' && call.fill === palette.warning));
    assert.ok(
      calls.some(
        (call) => call.name === 'fillText' && call.args[0].includes('Stopped') && call.fill === palette.warning,
      ),
    );
    assert.ok(
      calls.some(
        (call) => call.name === 'fillText' && call.args[0].includes('Tripped') && call.fill === palette.warning,
      ),
    );
  }
});

test('alarm pages follow HMI order and combine loops with active state first', () => {
  const view = viewFixture();
  view.alarms.find((alarm) => alarm.key === 'hot_leg_temperature_high:a').state = 'acknowledged';
  view.alarms.find((alarm) => alarm.key === 'hot_leg_temperature_high:b').state = 'active';
  view.alarms.find((alarm) => alarm.key === 'reactor_tripped').state = 'acknowledged';
  view.alarms.reverse();
  const calls = SCREEN_LAYOUTS.slice(2).flatMap((layout) => paint(view, layout));
  const labels = texts(calls).filter((text) => !text.startsWith('HMI01') && !text.startsWith('Telemetry'));
  assert.deepEqual(
    labels.filter((_, i) => i % 2 === 0),
    [
      'Subcooling margin low',
      'Pressurizer pressure high',
      'Pressurizer pressure low',
      'Pressurizer level high',
      'Pressurizer level low',
      'Hot leg temperature high',
      'Steam generator level low',
      'Steam generator level high',
      'Coolant flow low',
      'Condenser pressure high',
      'Neutron power high',
      'Reactor tripped',
      'Turbine tripped',
      'Coolant pump stopped',
      'Feed pump stopped',
      'Relief valve open',
    ],
  );
  assert.equal(labels[labels.indexOf('Hot leg temperature high') + 1], 'Active');
  assert.equal(labels[labels.indexOf('Reactor tripped') + 1], 'Acknowledged');
  assert.ok(calls.some((call) => call.name === 'fillRect' && call.fill === palette.warning));
  assert.ok(calls.some((call) => call.name === 'fillRect' && call.fill === palette.lampGlow));
  assert.ok(texts(paint(view, 'primary')).includes('Alarms: 1 active · 1 acknowledged'));
});

test('null alarm slots become normal grey tiles and only active alarms are counted', () => {
  const snapshots = JSON.parse(readFileSync(new URL('./fixtures/gate-run-extremes.json', import.meta.url), 'utf8'));
  const snapshot = snapshots[0];
  snapshot.alarms.fill(null);
  snapshot.alarms[0] = { alarm: { coolant_flow_low: 'b' }, state: 'active' };
  snapshot.alarms[1] = { alarm: 'coolant_pump_tripped', state: 'active' };
  const view = instruments(snapshot);
  assert.equal(view.alarms.length, 2);
  const calls = SCREEN_LAYOUTS.slice(2).flatMap((layout) => paint(view, layout));
  const normal = calls.filter((call) => call.name === 'fillText' && call.args[0] === 'Normal');
  assert.equal(normal.length, 14);
  assert.ok(normal.every((call) => call.fill === palette.text));
  assert.equal(texts(calls).filter((text) => text === 'Active').length, 2);
  assert.ok(!texts(calls).includes('Unavailable'));
  for (const layout of SCREEN_LAYOUTS.slice(0, 2)) {
    assert.ok(texts(paint(view, layout)).includes('Alarms: 2 active · 0 acknowledged'));
  }
});

function luminance(hex) {
  const channels = hex.match(/[\da-f]{2}/g).map((channel) => {
    const value = parseInt(channel, 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

test('alarm tiles have tinted surfaces, colored left bars and AA text in every palette', () => {
  const css = readFileSync(new URL('./viewer.css', import.meta.url), 'utf8');
  const palettes = [...css.matchAll(/--surface:\s*#[\da-f]+;[\s\S]*?--coolant-hot:\s*#[\da-f]+;/g)];
  assert.equal(palettes.length, 3);
  for (const [index, [block]] of palettes.entries()) {
    const tokens = Object.fromEntries(
      [...block.matchAll(/(--[\w-]+):\s*(#[\da-f]+);/g)].map(([, name, color]) => [name, color]),
    );
    const colors = Object.fromEntries(Object.entries(PALETTE_TOKENS).map(([name, token]) => [name, tokens[token]]));
    const view = viewFixture();
    view.alarms[0].state = 'active';
    view.alarms[1].state = 'acknowledged';
    const ctx = context();
    paintDeskScreen(ctx, { view, palette: colors, layout: 'alarms-primary' });
    for (let i = 0; i < 8; i += 1) {
      const x = 16 + (i % 2) * 504;
      const y = 52 + Math.floor(i / 2) * 100;
      const background = ctx.calls.find(
        (call) => call.name === 'fillRect' && call.args[0] === x && call.args[1] === y && call.args[2] === 488,
      );
      const bar = ctx.calls.find(
        (call) => call.name === 'fillRect' && call.args[0] === x && call.args[1] === y && call.args[2] === 6,
      );
      assert.equal(background.fill, i < 2 ? colors.sunken : colors.raised);
      if (i === 0) assert.equal(bar.fill, colors.warning);
      if (i === 1) assert.equal(bar.fill, colors.lampGlow);
      const labels = ctx.calls.filter(
        (call) => call.name === 'fillText' && call.args[1] === x + 12 && [y + 10, y + 45].includes(call.args[2]),
      );
      assert.equal(labels.length, 2);
      for (const label of labels) {
        const foreground = luminance(label.fill);
        const surface = luminance(background.fill);
        const contrast = (Math.max(foreground, surface) + 0.05) / (Math.min(foreground, surface) + 0.05);
        assert.ok(contrast >= 4.5, `Palette ${index}: ${label.args[0]} contrast ${contrast}`);
      }
    }
  }
});

test('every fill and stroke comes from the supplied palette', () => {
  const view = viewFixture();
  view.reportedStatus.coolantPumpsRunning[0] = false;
  view.alarms[0].state = 'active';
  view.alarms[1].state = 'acknowledged';
  const colors = new Set(Object.values(palette));
  for (const layout of SCREEN_LAYOUTS) {
    for (const call of paint(view, layout)) {
      if (['fill', 'fillRect', 'fillText'].includes(call.name)) assert.ok(colors.has(call.fill), call.fill);
      if (['stroke', 'strokeRect'].includes(call.name)) assert.ok(colors.has(call.stroke), call.stroke);
    }
  }
});

test('signatures track displayed values, status, alarms and heartbeat, but ignore truth and rounding noise', () => {
  const view = viewFixture();
  const initial = signature(view, 'primary');
  view.pairs.find((pair) => pair.key === 'hot_leg:b').reported = 324.6;
  assert.notEqual(signature(view, 'primary'), initial);
  const updated = signature(view, 'primary');
  view.pairs.find((pair) => pair.key === 'hot_leg:b').reported = 324.601;
  view.pairs.forEach((pair) => {
    pair.trueValue = 999;
  });
  view.atMs += 1000;
  assert.equal(signature(view, 'primary'), updated);
  view.reportedStatus.coolantPumpsRunning[0] = false;
  assert.notEqual(signature(view, 'primary'), updated);
  const alarm = signature(view, 'alarms-primary');
  view.alarms[0].state = 'active';
  assert.notEqual(signature(view, 'alarms-primary'), alarm);
  for (const layout of SCREEN_LAYOUTS) {
    const before = signature(view, layout);
    view.telemetry.heartbeat += 1;
    assert.notEqual(signature(view, layout), before);
  }
});

test('missing readings and alarms stay unavailable, and the painter preserves context state', () => {
  const view = viewFixture();
  view.pairs[0].reported = null;
  view.pairs.splice(1, 1);
  const labels = texts(paint(view, 'primary'));
  assert.equal(labels[labels.indexOf('NI-41') + 1], '—');
  assert.equal(labels[labels.indexOf('ZT-401') + 1], '—');
  const ctx = context();
  paintDeskScreen(ctx, { width: 512, height: 256, view: undefined, palette, layout: 'alarms-primary' });
  assert.equal(ctx.calls[0].name, 'save');
  assert.deepEqual(ctx.calls[1].args, [0.5, 0.5]);
  assert.equal(ctx.calls.at(-1).name, 'restore');
  assert.equal(texts(ctx.calls).filter((text) => text === 'Unavailable').length, 8);
  assert.ok(texts(ctx.calls).includes('Telemetry unavailable · heartbeat not yet read'));
});
