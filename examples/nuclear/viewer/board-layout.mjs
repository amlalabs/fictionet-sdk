// Dimensions are in meters. Canvas boxes use pixels on the flat board faces.
import { alarmLabel } from './instruments.mjs';

export const ROOM = Object.freeze({ width: 12, depth: 12, height: 3.65, eye: 1.65, radius: 0.22, fov: 76 });
export const FLOOR = Object.freeze({ tile: 0.6, seam: 0.025, thickness: 0.05 });
export const CEILING_LIGHTS = Object.freeze({
  xs: [-4, -1.3, 1.3, 4], zs: [-3.5, -1, 2, 4.5], width: 1.4, depth: 0.7,
});
export const DEFAULT_VIEW = 'control-room';
export const BOARD = Object.freeze({ width: 4.4, bottom: 1.05, top: 3.25, deskY: 0.9, deskDepth: 0.85, slope: 0.14 });
export const BOARD_PX = Object.freeze({ width: 1600, height: 800 });
export const BOARDS = Object.freeze([
  { title: 'Reactor board', view: 'reactor-board', x: -3.7, z: -1, yaw: Math.PI / 2,
    points: ['hot_leg:a', 'hot_leg:b', 'core_exit_temperature', 'neutron_power', 'pressurizer_pressure', 'pressurizer_level'] },
  { title: 'Loops board', view: 'loops-board', x: 0, z: -3.2, yaw: 0,
    points: ['rod_position', 'cold_leg:a', 'cold_leg:b', 'coolant_flow:a', 'coolant_flow:b', 'steam_flow:a', 'steam_flow:b', 'feed_flow:a', 'feed_flow:b'] },
  { title: 'Turbine board', view: 'turbine-board', x: 3.7, z: -1, yaw: -Math.PI / 2,
    points: ['steam_pressure', 'steam_generator_level:a', 'steam_generator_level:b', 'turbine_valve', 'generator_output', 'condenser_pressure'] },
]);

// Each alarm keeps its engraved window even when clear.
export const ANNUNCIATOR_WINDOWS = Object.freeze([
  ...['pressurizer_pressure_high', 'pressurizer_pressure_low', 'pressurizer_level_high', 'pressurizer_level_low',
    'relief_valve_open', 'reactor_tripped', 'neutron_power_high', 'subcooling_margin_low'].map(key => ({ key, board: 'reactor-board' })),
  ...['hot_leg_temperature_high:a', 'hot_leg_temperature_high:b', 'steam_generator_level_low:a', 'steam_generator_level_low:b',
    'steam_generator_level_high:a', 'steam_generator_level_high:b', 'feed_flow_low:a', 'feed_flow_low:b',
    'coolant_flow_low:a', 'coolant_flow_low:b', 'feed_pump_tripped', 'coolant_pump_tripped'].map(key => ({ key, board: 'loops-board' })),
  ...['turbine_tripped', 'condenser_vacuum_low'].map(key => ({ key, board: 'turbine-board' })),
].map(window => Object.freeze({ ...window, legend: alarmLabel(window.key) })));

export function windowState(state, timeMs, reducedMotion = false) {
  const unacknowledged = state === 'active';
  return { lit: state === 'acknowledged' || (unacknowledged && (reducedMotion || Math.floor(timeMs / 250) % 2 === 0)),
    mark: unacknowledged && reducedMotion };
}

export const DESKS = Object.freeze([
  { x: -1.5, z: 1.7, w: 2.1, d: 0.85, supervisor: false },
  { x: 1.5, z: 1.7, w: 2.1, d: 0.85, supervisor: false },
  { x: 0, z: 4.6, w: 2.6, d: 0.9, supervisor: true },
]);
export const CHAIRS = Object.freeze(DESKS.map(d => ({ x: d.x, z: d.z + 0.85 })));
export const CCTV = Object.freeze({ x: -5.86, y: 2.1, z: 3.1, width: 1.6, height: 0.9 });
export const DOOR = Object.freeze({ x: 4.5, z: 5.87, width: 1.25, height: 2.3 });
export const STANDING_SPOTS = Object.freeze({
  'control-room': { name: 'Control room', x: 2.6, z: 4.8, yaw: 0.3, pitch: 0 },
  'reactor-board': { name: 'Reactor board', x: -1.15, z: -1, yaw: Math.PI / 2, pitch: 0.02 },
  'loops-board': { name: 'Loops board', x: 0, z: -0.65, yaw: 0, pitch: 0.02 },
  'turbine-board': { name: 'Turbine board', x: 1.15, z: -1, yaw: -Math.PI / 2, pitch: 0.02 },
  cctv: { name: 'CCTV monitor', x: -3.1, z: 3.1, yaw: Math.PI / 2, pitch: 0.05 },
  door: { name: 'Door to the plant', x: 4.5, z: 2.9, yaw: Math.PI, pitch: 0.02 },
});

export function boardPoint(board, x, y, z) {
  return { x: board.x + Math.cos(board.yaw) * x + Math.sin(board.yaw) * z,
    y, z: board.z - Math.sin(board.yaw) * x + Math.cos(board.yaw) * z };
}
const box = (x, z, w, d) => ({ minX: x - w / 2, maxX: x + w / 2, minZ: z - d / 2, maxZ: z + d / 2 });
export const COLLISIONS = Object.freeze([
  box(-6, 0, 0.24, 12), box(6, 0, 0.24, 12), box(0, -6, 12, 0.24), box(0, 6, 12, 0.24),
  ...BOARDS.map(b => {
    const p = boardPoint(b, 0, 0, (BOARD.deskDepth - 0.2) / 2);
    return box(p.x, p.z, b.yaw === 0 ? BOARD.width + 0.1 : BOARD.deskDepth + 0.2,
      b.yaw === 0 ? BOARD.deskDepth + 0.2 : BOARD.width + 0.1);
  }),
  ...DESKS.map(d => box(d.x, d.z, d.w, d.d)),
  ...CHAIRS.map(c => box(c.x, c.z, 0.6, 0.6)),
]);

export function gapLayout(box, textWidth, marked = true) {
  const space = 6;
  const warningWidth = marked ? box.font : 0;
  const width = textWidth + warningWidth + (marked ? space : 0);
  const x = box.x + (box.w - width) / 2;
  return {
    warning: { x, y: box.y, w: warningWidth, h: box.h },
    text: { ...box, x: x + warningWidth + (marked ? space : 0), w: textWidth },
  };
}

export function cellLayout(width, height) {
  const font = Math.min(width * 0.055, height * 0.13);
  const line = font * 1.08;
  const pad = height * 0.006;
  const radius = Math.min(width * 0.16, (height - 5 * line - 8 * pad) / 2);
  const box = (x, y, w) => ({ x, y, w, h: line, font });
  const dialY = 2 * line + 3 * pad;
  const valueY = dialY + 2 * radius + pad;
  const gapLine = box(width * 0.03, valueY + line + pad, width * 0.94);
  const gap = gapLayout(gapLine, width * 0.83);
  return {
    gapLine,
    text: {
      label: box(width * 0.03, pad, width * 0.94),
      hmi: box(width * 0.03, line + 2 * pad, width * 0.44),
      plant: box(width * 0.53, line + 2 * pad, width * 0.44),
      reported: box(width * 0.03, valueY, width * 0.44),
      truth: box(width * 0.53, valueY, width * 0.44),
      gap: gap.text,
      held: box(width * 0.03, valueY + 2 * (line + pad), width * 0.94),
    },
    dials: [0.25, 0.75].map((x) => ({ x: width * x - radius, y: dialY, w: 2 * radius, h: 2 * radius, radius })),
    warning: gap.warning,
    // The ring is inside the dial so its full stroke has reserved space.
    ringWidth: Math.min(width * 0.055, radius * 0.25),
  };
}

export function boardLayout(count, board = BOARDS.find(b => b.points.length === count)?.view) {
  const { width, height } = BOARD_PX;
  const headerHeight = 62;
  const meterTop = 245;
  const font = 27;
  const textBox = (x, y, w) => ({ x, y, w, h: 30, font });
  const cellW = width / 3;
  const cellH = (height - meterTop) / Math.ceil(count / 3);
  const windows = ANNUNCIATOR_WINDOWS.filter(w => w.board === board).map((window, i) => ({ ...window,
    x: 12 + i % 4 * 397, y: 70 + Math.floor(i / 4) * 55, w: 385, h: 48, font: 23,
  }));
  return {
    header: { x: 0, y: 0, w: width, h: headerHeight },
    text: { title: textBox(16, 1, 840), time: textBox(900, 1, 684), telemetry: textBox(16, 31, 1568) },
    windows,
    cells: Array.from({ length: count }, (_, i) => ({ x: i % 3 * cellW, y: meterTop + Math.floor(i / 3) * cellH, w: cellW, h: cellH })),
  };
}
