import { FAULT_SENSORS } from './knobs.mjs';

export const SCREEN_LAYOUTS = Object.freeze(['primary', 'secondary', 'alarms-primary', 'alarms-secondary']);

const PRIMARY = [
  'neutron_power',
  'rod_position',
  'core_exit_temperature',
  'pressurizer_pressure',
  'pressurizer_level',
  'hot_leg:a',
  'hot_leg:b',
  'cold_leg:a',
  'cold_leg:b',
  'coolant_flow:a',
  'coolant_flow:b',
];
const SECONDARY = [
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
];

// The HMI combines loop alarms into one tile. Keep its tile order.
const ALARMS = [
  ['Subcooling margin low', 'subcooling_margin_low'],
  ['Pressurizer pressure high', 'pressurizer_pressure_high'],
  ['Pressurizer pressure low', 'pressurizer_pressure_low'],
  ['Pressurizer level high', 'pressurizer_level_high'],
  ['Pressurizer level low', 'pressurizer_level_low'],
  ['Hot leg temperature high', 'hot_leg_temperature_high:a', 'hot_leg_temperature_high:b'],
  ['Steam generator level low', 'steam_generator_level_low:a', 'steam_generator_level_low:b'],
  ['Steam generator level high', 'steam_generator_level_high:a', 'steam_generator_level_high:b'],
  ['Coolant flow low', 'coolant_flow_low:a', 'coolant_flow_low:b'],
  ['Condenser pressure high', 'condenser_vacuum_low'],
  ['Neutron power high', 'neutron_power_high'],
  ['Reactor tripped', 'reactor_tripped'],
  ['Turbine tripped', 'turbine_tripped'],
  ['Coolant pump stopped', 'coolant_pump_tripped'],
  ['Feed pump stopped', 'feed_pump_tripped'],
  ['Relief valve open', 'relief_valve_open'],
];

function valueText(pair) {
  if (!Number.isFinite(pair?.reported)) return '—';
  let digits = 1;
  if (pair.unit === 'MPa') digits = 2;
  if (pair.unit === 'pcm') digits = 0;
  return `${pair.reported.toFixed(digits)} ${pair.unit}`;
}

function alarmTiles(view) {
  return ALARMS.map(([label, ...keys]) => {
    const states = keys.map((key) => view?.alarms?.find((alarm) => alarm.key === key)?.state ?? 'normal');
    let state = 'Unavailable';
    if (view?.alarms && states.every((state) => state === 'normal')) state = 'Normal';
    if (states.includes('acknowledged')) state = 'Acknowledged';
    if (states.includes('active')) state = 'Active';
    return { label, state };
  });
}

function contents(view, layout) {
  if (!SCREEN_LAYOUTS.includes(layout)) throw new RangeError('Unknown desk screen layout');
  const allAlarms = alarmTiles(view);
  let linkState = 'unavailable';
  if (view?.telemetry?.quiet === false) linkState = 'live';
  if (view?.telemetry?.quiet === true) linkState = 'quiet · held';
  const link = `Telemetry ${linkState} · heartbeat ${view?.telemetry?.heartbeat ?? 'not yet read'}`;
  if (layout.startsWith('alarms')) {
    const start = layout === 'alarms-primary' ? 0 : 8;
    return { title: `HMI01 · ALARMS ${start / 8 + 1}/2`, link, alarms: allAlarms.slice(start, start + 8) };
  }
  const rs = view?.reportedStatus ?? {};
  const keys = layout === 'primary' ? PRIMARY : SECONDARY;
  const readings = keys.map((key) => {
    const pair = view?.pairs?.find((pair) => pair.key === key);
    return { tag: FAULT_SENSORS.find((sensor) => sensor.key === key).tag, value: valueText(pair) };
  });
  let status;
  if (layout === 'primary') {
    status = [
      rs.reactorTripped,
      rs.pressurizerHeatersOn,
      rs.pressurizerReliefOpen,
      ...[0, 1].map((i) => rs.coolantPumpsRunning?.[i]),
    ];
  } else {
    status = [
      rs.turbineTripped,
      rs.steamReliefOpen,
      ...[0, 1].map((i) => rs.feedPumpsRunning?.[i]),
      rs.auxiliaryFeedRunning,
      rs.circulatingWaterRunning,
    ];
  }
  const active = allAlarms.filter((alarm) => alarm.state === 'Active').length;
  const acknowledged = allAlarms.filter((alarm) => alarm.state === 'Acknowledged').length;
  return { title: `HMI01 · ${layout.toUpperCase()} OVERVIEW`, link, readings, status, active, acknowledged };
}

// Only display data enters the cache key. No clock or plant truth is read.
export function signature(view, layout) {
  return JSON.stringify(contents(view, layout));
}

/** Paint at a logical 1024 by 512, preserving the caller's canvas state. */
export function paintDeskScreen(ctx, { width = 1024, height = 512, view, palette, layout = SCREEN_LAYOUTS[0] }) {
  const data = contents(view, layout);
  const p = palette;
  ctx.save();
  ctx.scale(width / 1024, height / 512);
  ctx.textAlign = 'left';
  ctx.textBaseline = 'top';
  ctx.lineWidth = 2;
  const text = (value, x, y, size = 20, color = p.ink) => {
    ctx.fillStyle = color;
    ctx.font = `${size}px sans-serif`;
    ctx.fillText(value, x, y);
  };
  const box = (x, y, w, h, color = p.raised) => {
    ctx.fillStyle = color;
    ctx.strokeStyle = p.strongLine;
    ctx.fillRect(x, y, w, h);
    ctx.strokeRect(x, y, w, h);
  };
  const path = (points, color = p.strongLine, fill = false) => {
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.beginPath();
    points.forEach(([x, y], i) => {
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    if (fill) {
      ctx.closePath();
      ctx.fill();
    }
    ctx.stroke();
  };
  const circle = (x, y, radius, color = p.steel) => {
    ctx.fillStyle = color;
    ctx.strokeStyle = p.strongLine;
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
  };
  const valve = (x, y, abnormal) => {
    path(
      [
        [x - 12, y - 9],
        [x + 12, y + 9],
        [x + 12, y - 9],
        [x - 12, y + 9],
        [x - 12, y - 9],
      ],
      abnormal === true ? p.warning : p.steel,
      true,
    );
  };
  const stateText = (state, yes, no) => {
    if (state == null) return 'Unavailable';
    return state ? yes : no;
  };
  const pump = (x, y, label, running, abnormal = running === false) => {
    circle(x, y, 18, abnormal ? p.warning : p.steel);
    path([
      [x - 6, y - 8],
      [x + 9, y],
      [x - 6, y + 8],
    ]);
    text(`${label} ${stateText(running, 'Running', 'Stopped')}`, x - 65, y + 24, 18, abnormal ? p.warning : p.ink);
  };
  const vessel = (x, y, label, tripped, tubes = false) => {
    ctx.fillStyle = tripped === true ? p.warning : p.steel;
    ctx.strokeStyle = p.strongLine;
    ctx.beginPath();
    ctx.roundRect(x, y, 66, 86, 20);
    ctx.fill();
    ctx.stroke();
    if (tubes) {
      ctx.beginPath();
      ctx.moveTo(x + 21, y + 76);
      ctx.lineTo(x + 21, y + 28);
      ctx.quadraticCurveTo(x + 33, y + 2, x + 45, y + 28);
      ctx.lineTo(x + 45, y + 76);
      ctx.stroke();
    }
    text(label, x - 8, y - 24, 18);
  };

  ctx.fillStyle = p.surface;
  ctx.fillRect(0, 0, 1024, 512);
  text(data.title, 16, 10, 26);
  if (data.alarms) {
    data.alarms.forEach((alarm, i) => {
      const x = 16 + (i % 2) * 504;
      const y = 52 + Math.floor(i / 2) * 100;
      let color = p.strongLine;
      if (alarm.state === 'Active') color = p.warning;
      if (alarm.state === 'Acknowledged') color = p.lampGlow;
      const abnormal = alarm.state === 'Active' || alarm.state === 'Acknowledged';
      box(x, y, 488, 88, abnormal ? p.sunken : p.raised);
      ctx.fillStyle = color;
      ctx.fillRect(x, y, 6, 88);
      text(alarm.label, x + 12, y + 10, 26, abnormal ? p.ink : p.text);
      text(alarm.state, x + 12, y + 45, 26, abnormal ? p.ink : p.text);
    });
  } else {
    const s = data.status;
    if (layout === 'primary') {
      path([
        [156, 132],
        [450, 132],
      ]);
      path([
        [516, 132],
        [900, 132],
      ]);
      path([
        [123, 176],
        [123, 200],
        [450, 200],
      ]);
      path([
        [933, 176],
        [933, 200],
        [516, 200],
      ]);
      path([
        [693, 150],
        [693, 166],
        [840, 166],
        [840, 132],
      ]);
      path([
        [726, 82],
        [800, 82],
      ]);
      vessel(450, 114, 'Reactor', s[0]);
      for (const x of [470, 482, 494])
        path([
          [x, 124],
          [x, 174],
        ]);
      text(stateText(s[0], 'Tripped', 'Clear'), 440, 208, 18, s[0] === true ? p.warning : p.ink);
      vessel(660, 64, 'Pressurizer');
      valve(770, 82, s[2]);
      valve(620, 132);
      text(`Heaters ${stateText(s[1], 'On', 'Off')}`, 740, 105, 18);
      vessel(90, 90, 'SG A', false, true);
      vessel(900, 90, 'SG B', false, true);
      pump(285, 200, 'RCP A', s[3]);
      pump(760, 200, 'RCP B', s[4]);
    } else {
      path([
        [70, 152],
        [70, 84],
        [720, 84],
        [720, 194],
        [970, 194],
        [970, 228],
        [70, 228],
        [70, 180],
      ]);
      path([
        [250, 152],
        [250, 84],
      ]);
      path([
        [250, 180],
        [250, 228],
      ]);
      vessel(36, 128, 'SG A', false, true);
      vessel(216, 128, 'SG B', false, true);
      valve(380, 84, s[1]);
      valve(480, 84);
      for (const [x, label] of [
        [540, 'HP'],
        [640, 'LP'],
      ]) {
        path(
          [
            [x, 72],
            [x + 65, 52],
            [x + 65, 116],
            [x, 96],
            [x, 72],
          ],
          s[0] === true ? p.warning : p.steel,
          true,
        );
        text(label, x + 18, 72, 22);
      }
      text(`Turbine ${stateText(s[0], 'Tripped', 'Clear')}`, 530, 125, 18, s[0] === true ? p.warning : p.ink);
      path([
        [705, 84],
        [804, 84],
      ]);
      circle(830, 84, 26);
      text('G', 820, 71, 26);
      text('Generator', 885, 72, 20);
      box(855, 154, 145, 58, p.steel);
      for (const y of [166, 180, 194])
        path([
          [862, y],
          [993, y],
        ]);
      text('Condenser', 870, 130, 18);
      valve(135, 228);
      valve(315, 228);
      pump(395, 190, 'FW A', s[2]);
      pump(545, 190, 'FW B', s[3]);
      pump(690, 190, 'Aux', s[4], s[4] === true);
      pump(810, 190, 'CW', s[5]);
    }
    data.readings.forEach((reading, i) => {
      const x = 16 + (i % 6) * 168;
      const y = 258 + Math.floor(i / 6) * 82;
      box(x, y, 158, 72, p.sunken);
      text(reading.tag, x + 6, y + 7, 20);
      text(reading.value, x + 6, y + 34, 28);
    });
    box(16, 432, 992, 36, p.raised);
    text(
      `Alarms: ${data.active} active · ${data.acknowledged} acknowledged`,
      26,
      437,
      24,
      data.active > 0 ? p.warning : p.ink,
    );
  }
  text(data.link, 16, 480, 26);
  ctx.restore();
}

export const SITE_EPOCH_SECONDS = 1773474192;

export function siteTime(atMs) {
  if (!Number.isFinite(atMs)) return 'TIME UNAVAILABLE';
  const date = new Date(SITE_EPOCH_SECONDS * 1000 + atMs);
  return `${date.toISOString().slice(0, 19).replace('T', ' ')} GMT`;
}
