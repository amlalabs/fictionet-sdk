// Dimensions are in meters. Canvas boxes use pixels on the flat board faces.
import { alarmLabel } from './instruments.mjs';

export const ROOM = Object.freeze({ width: 14, depth: 14, height: 3.05, eye: 1.65, radius: 0.22, fov: 76 });
export const FLOOR = Object.freeze({ tile: 0.6, seam: 0.025, thickness: 0.05 });
export const CEILING_LIGHTS = Object.freeze({
  xs: [-4.2, -1.4, 1.4, 4.2], zs: [-3.6, -0.6, 2.4, 5.4], width: 1.2, depth: 0.6,
});
export const DEFAULT_VIEW = 'control-room';
export const BOARD = Object.freeze({ width: 2.8, bottom: 0.7, top: 2.9, deskY: 0.9, deskDepth: 0.6, slope: 0.14 });
export const BOARD_PX = Object.freeze({ width: 1400, height: 1100 });
const sections = [
  { id: 'rps', title: 'RPS / rods', name: 'RPS and rods', degrees: 55,
    points: ['neutron_power', 'rod_position', 'core_exit_temperature'] },
  { id: 'rcs', title: 'RCS / pressurizer', name: 'Pressurizer', degrees: 25,
    points: ['pressurizer_pressure', 'coolant_flow:a', 'pressurizer_level', 'coolant_flow:b'] },
  { id: 'loops', title: 'Loops', name: 'Loops', degrees: 0,
    points: ['hot_leg:a', 'cold_leg:a', 'hot_leg:b', 'cold_leg:b'] },
  { id: 'feed', title: 'Steam generators / feed', name: 'Steam generators', degrees: -25,
    points: ['steam_generator_level:a', 'feed_flow:a', 'steam_flow:a', 'steam_generator_level:b', 'feed_flow:b', 'steam_flow:b'] },
  { id: 'turbine', title: 'Turbine / condenser', name: 'Turbine', degrees: -55,
    points: ['steam_pressure', 'turbine_valve', 'generator_output', 'condenser_pressure'] },
];
// Successive panel tangents share an endpoint, including through the two bends.
const segments = sections.map(s => ({ ...s, view: `${s.id}-board`, width: BOARD.width, yaw: s.degrees * Math.PI / 180 }));
segments[2].x = 0;
segments[2].z = -4.4;
for (const [index, neighbor, direction] of [[1, 2, -1], [0, 1, -1], [3, 2, 1], [4, 3, 1]]) {
  const a = segments[neighbor];
  const b = segments[index];
  b.x = a.x + direction * BOARD.width / 2 * (Math.cos(a.yaw) + Math.cos(b.yaw));
  b.z = a.z - direction * BOARD.width / 2 * (Math.sin(a.yaw) + Math.sin(b.yaw));
}
export const BOARDS = Object.freeze(segments.map(Object.freeze));
export const HORSESHOE_CENTER = Object.freeze({ x: 0, z: 1.6 });

// Each alarm keeps its engraved window even when clear.
export const ANNUNCIATOR_WINDOWS = Object.freeze([
  ...['neutron_power_high', 'reactor_tripped', 'subcooling_margin_low'].map(key => ({ key, board: 'rps-board' })),
  ...['pressurizer_pressure_high', 'pressurizer_pressure_low', 'pressurizer_level_high', 'pressurizer_level_low',
    'relief_valve_open', 'coolant_flow_low:a', 'coolant_flow_low:b', 'coolant_pump_tripped'].map(key => ({ key, board: 'rcs-board' })),
  ...['hot_leg_temperature_high:a', 'hot_leg_temperature_high:b'].map(key => ({ key, board: 'loops-board' })),
  ...['steam_generator_level_low:a', 'steam_generator_level_low:b', 'steam_generator_level_high:a',
    'steam_generator_level_high:b', 'feed_flow_low:a', 'feed_flow_low:b', 'feed_pump_tripped'].map(key => ({ key, board: 'feed-board' })),
  ...['turbine_tripped', 'condenser_vacuum_low'].map(key => ({ key, board: 'turbine-board' })),
].map(window => Object.freeze({ ...window, legend: alarmLabel(window.key) })));

export function windowState(state, timeMs, reducedMotion = false) {
  const unacknowledged = state === 'active';
  return { lit: state === 'acknowledged' || (unacknowledged && (reducedMotion || Math.floor(timeMs / 250) % 2 === 0)),
    mark: unacknowledged && reducedMotion };
}

export const DESKS = Object.freeze([
  { x: -1.65, z: -1.1, w: 2.1, d: 0.85, supervisor: false },
  { x: 1.65, z: -1.1, w: 2.1, d: 0.85, supervisor: false },
  { x: 0, z: 5.8, w: 2.6, d: 0.9, supervisor: true },
]);
// Chairs are parked behind the standing operator, clear of the view into the U.
export const CHAIRS = Object.freeze([{ x: -2.8, z: 5.2 }, { x: 2.8, z: 5.2 }, { x: 0, z: 6.55 }]);
export const CCTV = Object.freeze({ x: -6.86, y: 1.65, z: 3.1, width: 4.15, height: 4.15 * 9 / 16, bankWidth: 5.05, bankHeight: 4.15 * 9 / 16 + 0.2 });
export const DOOR = Object.freeze({ x: 4.5, z: 6.87, width: 1.25, height: 2.3 });

export function boardPoint(board, x, y, z) {
  return { x: board.x + Math.cos(board.yaw) * x + Math.sin(board.yaw) * z,
    y, z: board.z - Math.sin(board.yaw) * x + Math.cos(board.yaw) * z };
}

export function deskOutline(segment) {
  const index = BOARDS.indexOf(segment);
  const previous = BOARDS[index - 1];
  const next = BOARDS[index + 1];
  const leftInset = previous ? Math.tan((previous.yaw - segment.yaw) / 2) * BOARD.deskDepth : 0;
  const rightInset = next ? Math.tan((segment.yaw - next.yaw) / 2) * BOARD.deskDepth : 0;
  return [
    { x: -BOARD.width / 2, z: 0 }, { x: BOARD.width / 2, z: 0 },
    { x: BOARD.width / 2 - rightInset, z: BOARD.deskDepth },
    { x: -BOARD.width / 2 + leftInset, z: BOARD.deskDepth },
  ];
}

// Vertical FOV is the camera input; the horizontal tangent follows the actual canvas aspect.
export function fitSpot(segment, aspect, fov = ROOM.fov) {
  if (!(aspect > 0) || !(fov > 0 && fov < 180)) throw new RangeError('Invalid camera dimensions');
  const vertical = Math.tan(fov * Math.PI / 360) * 0.92;
  const horizontal = vertical * aspect;
  const pitch = 0;
  const c = Math.cos(pitch);
  const s = Math.sin(pitch);
  const bottom = BOARD.deskY - Math.sin(BOARD.slope) * BOARD.deskDepth - 0.06;
  const bounds = [[BOARD.bottom, 0.09], [BOARD.top, 0.09], [bottom, BOARD.deskDepth], [BOARD.deskY, BOARD.deskDepth]];
  let distance = 0;
  for (const [y, z] of bounds) {
    const dy = y - ROOM.eye;
    distance = Math.max(distance,
      z + (BOARD.width / 2 / horizontal - s * dy) / c,
      z + (c - vertical * s) * dy / (s + vertical * c),
      z + (-c - vertical * s) * dy / (-s + vertical * c));
  }
  distance += 0.02;
  const position = boardPoint(segment, 0, ROOM.eye, distance);
  return { name: segment.name, x: position.x, z: position.z, yaw: segment.yaw, pitch, distance };
}

export const STANDING_SPOTS = Object.freeze({
  'control-room': { name: 'Control room', x: 0, z: 4.89, yaw: 0, pitch: -0.13, fov: 50.1 },
  ...Object.fromEntries(BOARDS.map(b => [b.view, { ...fitSpot(b, 16 / 10), fov: ROOM.fov }])),
  cctv: { name: 'CCTV monitor', x: -4.42, z: 3.1, yaw: Math.PI / 2, pitch: 0, fov: ROOM.fov },
  door: { name: 'Door to the plant', x: 4.5, z: 3.9, yaw: Math.PI, pitch: 0.02, fov: ROOM.fov },
});

export function meterCenter(segment, point) {
  const index = segment.points.indexOf(point);
  if (index < 0) throw new RangeError(`No meter for ${point} on ${segment.id}`);
  const cell = boardLayout(segment.points.length, segment.view).cells[index];
  return (cell.x + cell.w / 2) / BOARD_PX.width * BOARD.width - BOARD.width / 2;
}

export function devicePlacements(knobs) {
  const plant = knobs.filter(knob => knob.group === 'plant');
  return plant.map(knob => {
    const segment = BOARDS.find(board => board.id === knob.board);
    if (!segment) throw new RangeError(`No section for ${knob.id}`);
    const column = knob.point === null ? 0 : meterCenter(segment, knob.point);
    const neighbors = plant.filter(other => other.board === knob.board
      && (other.point === null ? 0 : meterCenter(segment, other.point)) === column);
    const offset = (neighbors.indexOf(knob) - (neighbors.length - 1) / 2) * 0.19;
    const x = (knob.point === null ? 0 : meterCenter(segment, knob.point)) + offset;
    return { id: knob.id, segment: segment.id, x, yaw: segment.yaw,
      position: boardPoint(segment, x, BOARD.deskY - Math.sin(BOARD.slope) * BOARD.deskDepth / 4, BOARD.deskDepth / 4),
      footprint: { x: x - 0.08, y: BOARD.deskDepth / 4 - 0.08, w: 0.16, h: 0.25 } };
  });
}

const box = (x, z, w, d) => ({ minX: x - w / 2, maxX: x + w / 2, minZ: z - d / 2, maxZ: z + d / 2 });
export const COLLISIONS = Object.freeze([
  box(-7, 0, 0.24, 14), box(7, 0, 0.24, 14), box(0, -7, 14, 0.24),
  box((-7 + DOOR.x - DOOR.width / 2) / 2, 7, DOOR.x - DOOR.width / 2 + 7, 0.24),
  box((7 + DOOR.x + DOOR.width / 2) / 2, 7, 7 - DOOR.x - DOOR.width / 2, 0.24),
  ...BOARDS.flatMap(b => Array.from({ length: 14 }, (_, i) => {
    const p = boardPoint(b, -BOARD.width / 2 + (i + 0.5) * 0.2, 0, (BOARD.deskDepth - 0.2) / 2);
    const c = Math.abs(Math.cos(b.yaw));
    const s = Math.abs(Math.sin(b.yaw));
    return box(p.x, p.z, c * 0.2 + s * (BOARD.deskDepth + 0.2), s * 0.2 + c * (BOARD.deskDepth + 0.2));
  })),
  box(CCTV.x - 0.01, CCTV.z - 0.35, 0.12, CCTV.bankWidth + 0.08),
  ...DESKS.map(d => box(d.x, d.z, d.w, d.d)),
  ...CHAIRS.map(c => box(c.x, c.z, 0.6, 0.6)),
]);

export function gapLayout(box, textWidth, marked = true) {
  const space = 6;
  const warningWidth = marked ? box.font : 0;
  const width = textWidth + warningWidth + (marked ? space : 0);
  const x = box.x + (box.w - width) / 2;
  const textX = x + warningWidth + (marked ? space : 0);
  return {
    warning: { x, y: box.y, w: textX - (marked ? space : 0) - x, h: box.h },
    text: { ...box, x: textX, w: textWidth },
  };
}

export function cellLayout(width, height) {
  const font = Math.min(37, height * 0.11);
  const labelFont = Math.min(34, font);
  const line = font + 2;
  const pad = Math.max(1, (height - 5 * line - 2 * width * 0.23) / 8);
  const radius = Math.min(width * 0.23, (height - 5 * line - 8 * pad) / 2);
  const box = (x, y, w, size = font) => ({ x, y, w, h: line, font: size, stretch: 0.85 });
  const dialY = 2 * line + 3 * pad;
  const valueY = dialY + 2 * radius + pad;
  const gapLine = box(width * 0.02, valueY + line + pad, width * 0.96);
  const gap = gapLayout(gapLine, width * 0.82);
  return {
    gapLine,
    text: {
      label: box(width * 0.02, pad, width * 0.96, labelFont),
      hmi: box(width * 0.02, line + 2 * pad, width * 0.46, labelFont),
      plant: box(width * 0.52, line + 2 * pad, width * 0.46, labelFont),
      reported: box(width * 0.02, valueY, width * 0.46),
      truth: box(width * 0.52, valueY, width * 0.46),
      gap: gap.text,
      held: box(width * 0.02, valueY + 2 * (line + pad), width * 0.96),
    },
    dials: [0.25, 0.75].map(x => ({ x: width * x - radius, y: dialY, w: 2 * radius, h: 2 * radius, radius })),
    warning: gap.warning,
    ringWidth: Math.min(width * 0.055, radius * 0.25),
  };
}

export function boardLayout(count, board = BOARDS.find(b => b.points.length === count)?.view) {
  const { width } = BOARD_PX;
  const columns = count === 4 ? 2 : Math.min(3, count);
  const rows = Math.ceil(count / columns);
  const headerHeight = 140;
  const meterTop = 275;
  const textBox = (x, y, w) => ({ x, y, w, h: 44, font: 34 });
  const cellW = width / columns;
  const cellH = 668 / rows;
  const alarms = ANNUNCIATOR_WINDOWS.filter(w => w.board === board);
  const windows = alarms.map((window, i) => ({ ...window,
    engraved: window.legend.replace('Steam generator', 'Steam gen.').replace(', loop ', ' '),
    x: (width - alarms.length * 78) / 2 + i * 78, y: 155, w: 70, h: 70, font: 9,
  }));
  return {
    header: { x: 0, y: 0, w: width, h: headerHeight },
    text: { title: textBox(16, 2, 1368), time: textBox(16, 48, 1368), telemetry: textBox(16, 94, 1368) },
    windows,
    cells: Array.from({ length: count }, (_, i) => ({
      x: i % columns * cellW, y: meterTop + Math.floor(i / columns) * cellH, w: cellW, h: cellH,
    })),
  };
}


export function mimicLines(segment) {
  if (!['rcs', 'loops', 'feed'].includes(segment.id)) return [];
  const layout = boardLayout(segment.points.length, segment.view);
  return ['a', 'b'].flatMap(loop => {
    const index = segment.points.findIndex(point => point.endsWith(`:${loop}`));
    const cell = layout.cells[index];
    const dial = cellLayout(cell.w, cell.h).dials[0];
    const center = cell.y + dial.y + dial.radius;
    const start = segment.id === 'rcs' ? cell.x + cell.w / 2 : 0;
    const end = segment.id === 'feed' ? cell.x + cell.w / 2 : BOARD_PX.width;
    return [
      { loop, start, end, y: center - dial.radius * 0.55, direction: 1, color: 'hotCoolant' },
      { loop, start, end, y: center + dial.radius * 0.55, direction: -1, color: 'coldCoolant' },
    ];
  });
}

// Door planes and room offsets use the same world frame as the control room.
export const PLANT_OFFSETS = Object.freeze({ reactor: { x: 4.5, z: 43 }, turbine: { x: -23.5, z: 20 } });
export const DOORWAYS = Object.freeze([
  { from: 'control-room', to: 'corridor', z: 7, minX: 3.875, maxX: 5.125 },
  { from: 'corridor', to: 'turbine', z: 11, minX: 3.875, maxX: 5.125 },
  { from: 'turbine', to: 'airlock', z: 29, minX: 3.875, maxX: 5.125 },
  { from: 'airlock', to: 'reactor', z: 33, minX: 3.875, maxX: 5.125 },
]);
export function passageCollisions(start, end) {
  return [box(3.725, (start + end) / 2, 0.3, end - start + 0.3),
    box(5.275, (start + end) / 2, 0.3, end - start + 0.3)];
}
