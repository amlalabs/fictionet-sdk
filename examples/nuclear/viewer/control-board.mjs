// The control room boards in 3D: a curved bank of three boards, an annunciator
// band across their tops, and a console of knobs in front of them.
//
// Each gauge is painted on a canvas face from instruments(snapshot). The
// reported dial is the HMI reading and the true dial is the plant itself. A
// diverged reported dial that a fault or a freeze explains gets one amber ring,
// a dashed line to its true twin, and the numeric gap in text and a triangle.
// Easing moves needles for the eye only. Every number printed is the value the
// snapshot gave.
//
// The panel loads this module inside mount, so a failed download of Three.js is
// reported in the panel and not at page load.

import * as THREE from '/vendor/three/build/three.module.js';
import { formatGap, formatValue } from './instruments.mjs';

const TAU = Math.PI * 2;
const RADIUS = 4.6;
const BOARD_SPAN = Math.PI / 9; // 20 degrees per board: three boards fit the view
const BOARD_BOTTOM = 0.95;
const BOARD_TOP = 3.05;
const BAND_BOTTOM = 3.12;
const BAND_TOP = 3.72;
const CONSOLE_Y = 0.92;
const CONSOLE_RADIUS = 3.85;
const CONSOLE_SPAN = (76 * Math.PI) / 180;
const NEEDLE_SMOOTH_S = 0.35;
const NEEDLE_SWEEP = (270 * Math.PI) / 180;
const NEEDLE_START = (135 * Math.PI) / 180;
const KNOB_SWEEP = (270 * Math.PI) / 180;
const VIEW_HALF_WIDTH = (33 * Math.PI) / 180; // keeps the whole bank in view
const VIEW_HALF_HEIGHT = (21 * Math.PI) / 180;
const EYE = [0, 1.9, 0];
const LOOK = [0, 2.25, -4.6];

const BOARD_PX = { width: 1024, height: 1280 };
const BOARD_HEADER_PX = 150;
const BAND_PX = { width: 2048, height: 256 };
/** Tiles in the annunciator band: two rows of nine. */
export const ANNUNCIATOR_SLOTS = 18;

const FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif";

/** Label lines for each gauge, short enough to fit a cell of the board. */
const LABELS = Object.freeze({
  'hot_leg:a': ['Hot leg A'],
  'hot_leg:b': ['Hot leg B'],
  core_exit_temperature: ['Core exit', 'temperature'],
  neutron_power: ['Neutron', 'power'],
  pressurizer_pressure: ['Pressurizer', 'pressure'],
  pressurizer_level: ['Pressurizer', 'level'],
  steam_pressure: ['Steam', 'pressure'],
  'steam_generator_level:a': ['Steam gen.', 'level A'],
  'steam_generator_level:b': ['Steam gen.', 'level B'],
  turbine_valve: ['Turbine', 'valve'],
  generator_output: ['Generator', 'output'],
  condenser_pressure: ['Condenser', 'pressure'],
  rod_position: ['Control rod', 'position'],
  'cold_leg:a': ['Cold leg A'],
  'cold_leg:b': ['Cold leg B'],
  'coolant_flow:a': ['Coolant flow A'],
  'coolant_flow:b': ['Coolant flow B'],
  'steam_flow:a': ['Steam flow A'],
  'steam_flow:b': ['Steam flow B'],
  'feed_flow:a': ['Feed flow A'],
  'feed_flow:b': ['Feed flow B'],
});

/** The three boards, reactor on the left and turbine hall on the right, as the plant is laid out. */
export const BOARDS = Object.freeze([
  {
    title: 'Reactor controls',
    center: Math.PI + BOARD_SPAN,
    cols: 3,
    points: ['hot_leg:a', 'hot_leg:b', 'core_exit_temperature', 'neutron_power', 'pressurizer_pressure', 'pressurizer_level'],
  },
  {
    title: 'Turbine hall',
    center: Math.PI - BOARD_SPAN,
    cols: 3,
    points: ['steam_pressure', 'steam_generator_level:a', 'steam_generator_level:b', 'turbine_valve', 'generator_output', 'condenser_pressure'],
  },
  {
    title: 'Loops and feed',
    center: Math.PI,
    cols: 3,
    points: [
      'rod_position',
      'cold_leg:a',
      'cold_leg:b',
      'coolant_flow:a',
      'coolant_flow:b',
      'steam_flow:a',
      'steam_flow:b',
      'feed_flow:a',
      'feed_flow:b',
    ],
  },
]);

const clamp01 = (v) => Math.min(1, Math.max(0, v));
const fractionOf = (value, [low, high]) => clamp01((value - low) / (high - low));

/**
 * Builds the control room in `container`. `knobIds` fixes the order of the
 * console knobs, and `update` takes their states in that order. `theme` maps
 * palette names to colors. `reducedMotion` is a function that says whether
 * motion is reduced right now. Returns update, setTheme and dispose.
 */
export function createControlBoard(container, { knobIds, theme, reducedMotion }) {
  const resources = [];
  const track = (resource) => {
    resources.push(resource);
    return resource;
  };

  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.domElement.setAttribute('role', 'img');
  renderer.domElement.setAttribute(
    'aria-label',
    'Three-dimensional view of the control room: three curved boards with paired gauges, an annunciator band and a console of knobs. The readings text lists the same values.',
  );
  container.append(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(40, 1, 0.1, 60);
  camera.position.set(...EYE);
  camera.lookAt(...LOOK);
  scene.add(new THREE.HemisphereLight(0xffffff, 0x8a8a80, 1.0));
  const sun = new THREE.DirectionalLight(0xffffff, 0.6);
  sun.position.set(0.5, 7, 3);
  scene.add(sun);

  // Materials take their colors from the page's palette in applyTheme().
  const material = {
    wall: track(new THREE.MeshLambertMaterial({ side: THREE.BackSide })),
    floor: track(new THREE.MeshLambertMaterial()),
    bezel: track(new THREE.MeshLambertMaterial({ side: THREE.DoubleSide })),
    steel: track(new THREE.MeshLambertMaterial({ side: THREE.DoubleSide })),
    ink: track(new THREE.MeshLambertMaterial()),
    accent: track(new THREE.MeshLambertMaterial()),
  };

  const room = new THREE.Mesh(track(new THREE.CylinderGeometry(9, 9, 7.4, 64, 1, true)), material.wall);
  room.position.y = 3.4;
  scene.add(room);
  const floor = new THREE.Mesh(track(new THREE.CircleGeometry(9, 64)), material.floor);
  floor.rotation.x = -Math.PI / 2;
  scene.add(floor);

  // One canvas per board, painted from the snapshot. The canvas is the texture.
  const boards = BOARDS.map((config) => {
    const canvas = document.createElement('canvas');
    canvas.width = BOARD_PX.width;
    canvas.height = BOARD_PX.height;
    const texture = canvasTexture(canvas, track);
    const face = new THREE.Mesh(
      track(arcGeometry(config.center, BOARD_SPAN, RADIUS, BOARD_BOTTOM, BOARD_TOP)),
      track(new THREE.MeshLambertMaterial({ map: texture, side: THREE.DoubleSide })),
    );
    scene.add(face);
    const bezel = new THREE.Mesh(
      track(arcGeometry(config.center, BOARD_SPAN + 0.02, RADIUS + 0.03, BOARD_BOTTOM - 0.06, BOARD_TOP + 0.06)),
      material.bezel,
    );
    scene.add(bezel);
    return { config, canvas, texture };
  });

  const bandCanvas = document.createElement('canvas');
  bandCanvas.width = BAND_PX.width;
  bandCanvas.height = BAND_PX.height;
  const bandTexture = canvasTexture(bandCanvas, track);
  const band = new THREE.Mesh(
    track(arcGeometry(Math.PI, 3 * BOARD_SPAN, RADIUS - 0.02, BAND_BOTTOM, BAND_TOP)),
    track(new THREE.MeshLambertMaterial({ map: bandTexture, side: THREE.DoubleSide })),
  );
  scene.add(band);

  // The console: a curved shelf ring in front of the boards, with one control per knob.
  const shelf = new THREE.Mesh(
    track(
      new THREE.RingGeometry(CONSOLE_RADIUS - 0.3, CONSOLE_RADIUS + 0.25, 96, 1, Math.PI / 2 - CONSOLE_SPAN / 2, CONSOLE_SPAN).rotateX(-Math.PI / 2),
    ),
    material.steel,
  );
  shelf.position.y = CONSOLE_Y;
  scene.add(shelf);
  const knobs = knobIds.map((id, i) => {
    const angle = knobArcAngle(i, knobIds.length);
    const group = new THREE.Group();
    group.position.set(CONSOLE_RADIUS * Math.sin(angle), CONSOLE_Y, -CONSOLE_RADIUS * Math.cos(angle));
    scene.add(group);
    return { id, place: makeKnob(group, material, track) };
  });

  let view = null;
  let text = null;
  let knobStates = [];
  let palette = null;
  let disposed = false;
  let visible = true;
  let raf = 0;
  let last = 0;
  let dirty = true;
  const shown = new Map();

  applyTheme(theme);

  function applyTheme(next) {
    palette = { ...next };
    scene.background = new THREE.Color(palette.sunken);
    material.wall.color.set(palette.sunken);
    material.floor.color.set(palette.line);
    material.bezel.color.set(palette.metal);
    material.steel.color.set(palette.metal);
    material.ink.color.set(palette.ink);
    material.accent.color.set(palette.accent);
    dirty = true;
  }

  const resize = () => {
    const width = Math.max(1, container.clientWidth);
    const height = Math.max(1, container.clientHeight);
    const aspect = width / height;
    // Vertical field of view: wide enough for the bank across, and never less than the height needs.
    const halfV = Math.max(VIEW_HALF_HEIGHT, Math.atan(Math.tan(VIEW_HALF_WIDTH) / aspect));
    camera.fov = (2 * halfV * 180) / Math.PI;
    renderer.setSize(width, height, false);
    camera.aspect = aspect;
    camera.updateProjectionMatrix();
    requestFrame();
  };
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(container);
  resize();

  const visibilityObserver = new IntersectionObserver((entries) => {
    visible = entries.some((entry) => entry.isIntersecting);
    if (visible) requestFrame();
  });
  visibilityObserver.observe(container);

  // Frames run only while something moves; an idle board draws nothing.
  function requestFrame() {
    if (raf === 0 && !disposed && visible) {
      last = performance.now();
      raf = requestAnimationFrame(frame);
    }
  }

  function frame(now) {
    raf = 0;
    if (disposed) return;
    const dt = Math.min(0.1, (now - last) / 1000);
    last = now;
    const moving = easeNeedles(dt);
    if (dirty || moving) {
      paintAll();
      dirty = false;
    }
    knobs.forEach((knob, i) => {
      if (knobStates[i]) knob.place(knobStates[i]);
    });
    renderer.render(scene, camera);
    if (moving) raf = requestAnimationFrame(frame);
  }

  // Needles ease toward the snapshot's fractions. Reduced motion takes them at once.
  function easeNeedles(dt) {
    if (!view) return false;
    const k = reducedMotion() ? 1 : 1 - Math.exp(-dt / NEEDLE_SMOOTH_S);
    let moving = false;
    for (const pair of view.pairs) {
      const current = shown.get(pair.key) ?? { reported: 0, truth: 0 };
      const goal = {
        reported: pair.reported === null ? 0 : fractionOf(pair.reported, pair.range),
        truth: fractionOf(pair.trueValue, pair.range),
      };
      const next = {
        reported: current.reported + (goal.reported - current.reported) * k,
        truth: current.truth + (goal.truth - current.truth) * k,
      };
      if (Math.abs(goal.reported - next.reported) > 1e-3 || Math.abs(goal.truth - next.truth) > 1e-3) moving = true;
      if (next.reported !== current.reported || next.truth !== current.truth) dirty = true;
      shown.set(pair.key, next);
    }
    return moving;
  }

  function paintAll() {
    if (!view || !text) return;
    for (const board of boards) {
      paintBoard(board);
      board.texture.needsUpdate = true;
    }
    paintBand();
    bandTexture.needsUpdate = true;
  }

  function paintBoard({ config, canvas }) {
    const ctx = canvas.getContext('2d');
    const { width, height } = BOARD_PX;
    const rows = Math.ceil(config.points.length / config.cols);
    const cellW = width / config.cols;
    const cellH = (height - BOARD_HEADER_PX) / rows;
    ctx.fillStyle = palette.raised;
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = palette.surface;
    ctx.fillRect(0, 0, width, BOARD_HEADER_PX);
    ctx.textBaseline = 'middle';
    ctx.textAlign = 'left';
    ctx.fillStyle = palette.ink;
    ctx.font = `700 58px ${FONT}`;
    ctx.fillText(config.title, 28, 56);
    ctx.font = `600 36px ${FONT}`;
    ctx.fillStyle = palette.text;
    ctx.fillText(`Plant time ${text.plantTime}`, 28, 112);
    ctx.textAlign = 'right';
    ctx.font = `600 32px ${FONT}`;
    ctx.fillText(text.telemetry, width - 28, 112);
    ctx.textAlign = 'left';
    config.points.forEach((key, index) => {
      const pair = view.pairs.find((p) => p.key === key);
      if (!pair) return;
      paintCell(ctx, pair, {
        x: (index % config.cols) * cellW,
        y: BOARD_HEADER_PX + Math.floor(index / config.cols) * cellH,
        w: cellW,
        h: cellH,
      });
    });
  }

  // A cell: the gauge name, a caption over each dial, the two dials, their values,
  // the gap, and a frozen gauge's stopped time. The reported dial is on the left.
  function paintCell(ctx, pair, cell) {
    const r = Math.min(cell.w * 0.16, cell.h * 0.15);
    const reportedX = cell.x + cell.w * 0.23;
    const trueX = cell.x + cell.w * 0.77;
    const midX = (reportedX + trueX) / 2;
    const lines = LABELS[pair.key] ?? [pair.label];
    const level = shown.get(pair.key) ?? { reported: 0, truth: 0 };

    ctx.save();
    ctx.textAlign = 'left';
    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = palette.ink;
    ctx.font = `700 40px ${FONT}`;
    lines.forEach((line, i) => ctx.fillText(line, cell.x + 22, cell.y + 48 + i * 44));
    const captionY = cell.y + 48 + 2 * 44 + 4;
    const cy = captionY + 22 + r;

    if (pair.marked) {
      // The single amber ring, and a dashed line from the HMI dial to its true twin.
      ctx.beginPath();
      ctx.arc(reportedX, cy, r + 12, 0, TAU);
      ctx.strokeStyle = palette.warning;
      ctx.lineWidth = 9;
      ctx.stroke();
      ctx.beginPath();
      ctx.setLineDash([12, 9]);
      ctx.moveTo(reportedX + r + 22, cy);
      ctx.lineTo(trueX - r - 22, cy);
      ctx.lineWidth = 5;
      ctx.stroke();
      ctx.setLineDash([]);
    }

    drawDial(ctx, reportedX, cy, r, pair.reported === null ? 0 : level.reported, {
      color: palette.ink,
      dashed: pair.frozen || pair.reported === null,
    });
    drawDial(ctx, trueX, cy, r, level.truth, { color: palette.accent });

    ctx.textAlign = 'center';
    ctx.font = `600 28px ${FONT}`;
    ctx.fillStyle = palette.text;
    ctx.fillText('HMI', reportedX, captionY + 20);
    ctx.fillText('Plant', trueX, captionY + 20);

    const valueY = cy + r + 50;
    ctx.font = `700 32px ${FONT}`;
    ctx.fillStyle = palette.ink;
    ctx.fillText(pair.reported === null ? 'no reading' : formatValue(pair.reported, pair.unit), reportedX, valueY);
    ctx.fillText(formatValue(pair.trueValue, pair.unit), trueX, valueY);

    // The gap is text and shape. A marked gap has a triangle with a bang as well as its color.
    const label = gapLabel(pair);
    const gapY = valueY + 44;
    ctx.font = `700 30px ${FONT}`;
    ctx.fillStyle = pair.marked ? palette.warning : palette.text;
    if (pair.marked) {
      const width = ctx.measureText(label).width;
      const left = midX - width / 2 - 42;
      const top = gapY - 26;
      ctx.beginPath();
      ctx.moveTo(left, top + 28);
      ctx.lineTo(left + 15, top);
      ctx.lineTo(left + 30, top + 28);
      ctx.closePath();
      ctx.fill();
      ctx.fillStyle = palette.surface;
      ctx.textAlign = 'center';
      ctx.fillText('!', left + 15, top + 23);
      ctx.fillStyle = palette.warning;
    }
    ctx.textAlign = 'center';
    ctx.fillText(label, midX, gapY);

    if (pair.frozen && text.held[pair.key]) {
      ctx.font = `600 26px ${FONT}`;
      ctx.fillStyle = palette.text;
      ctx.fillText(text.held[pair.key], midX, gapY + 38);
    }
    ctx.restore();
  }

  function gapLabel(pair) {
    if (pair.reported === null) return 'No instrument';
    const gap = formatGap(pair.gap, pair.unit);
    return pair.diverged && !pair.marked ? `Lagging ${gap}` : `Gap ${gap}`;
  }

  function drawDial(ctx, cx, cy, r, fraction, { color, dashed = false }) {
    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, TAU);
    ctx.fillStyle = palette.surface;
    ctx.fill();
    ctx.lineWidth = Math.max(5, r * 0.08);
    ctx.strokeStyle = color;
    if (dashed) ctx.setLineDash([10, 8]);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.lineWidth = Math.max(3, r * 0.05);
    for (let i = 0; i <= 8; i++) {
      const a = NEEDLE_START + (i / 8) * NEEDLE_SWEEP;
      ctx.beginPath();
      ctx.moveTo(cx + Math.cos(a) * r * 0.78, cy + Math.sin(a) * r * 0.78);
      ctx.lineTo(cx + Math.cos(a) * r * 0.9, cy + Math.sin(a) * r * 0.9);
      ctx.stroke();
    }
    const a = NEEDLE_START + clamp01(fraction) * NEEDLE_SWEEP;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(a) * r * 0.74, cy + Math.sin(a) * r * 0.74);
    ctx.lineWidth = Math.max(5, r * 0.09);
    ctx.lineCap = 'round';
    ctx.strokeStyle = color;
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(cx, cy, Math.max(5, r * 0.11), 0, TAU);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.restore();
  }

  function paintBand() {
    const ctx = bandCanvas.getContext('2d');
    const { width, height } = BAND_PX;
    const cols = ANNUNCIATOR_SLOTS / 2;
    const tileW = width / cols;
    const tileH = height / 2;
    const tiles = text.tiles;
    ctx.fillStyle = palette.surface;
    ctx.fillRect(0, 0, width, height);
    ctx.textBaseline = 'alphabetic';
    ctx.textAlign = 'left';
    for (let i = 0; i < ANNUNCIATOR_SLOTS; i++) {
      const tile = tiles[i] ?? null;
      const x = (i % cols) * tileW + 8;
      const y = Math.floor(i / cols) * tileH + 8;
      const w = tileW - 16;
      const h = tileH - 16;
      ctx.beginPath();
      roundRect(ctx, x, y, w, h, 14);
      if (!tile) {
        ctx.fillStyle = palette.sunken;
        ctx.fill();
        continue;
      }
      if (tile.state === 'active') {
        ctx.fillStyle = palette.warning;
        ctx.fill();
      } else {
        ctx.fillStyle = palette.raised;
        ctx.fill();
        ctx.lineWidth = 8;
        ctx.strokeStyle = palette.warning;
        ctx.stroke();
      }
      const inkOn = tile.state === 'active' ? palette.surface : palette.ink;
      const sub = tile.state === 'active' ? palette.surface : palette.text;
      ctx.fillStyle = inkOn;
      ctx.font = `700 30px ${FONT}`;
      // Two label lines, then the state line on its own baseline at the foot of the tile.
      const lines = wrapLines(ctx, `${tile.state === 'active' ? '! ' : ''}${tile.label}`, w - 36, 2);
      lines.forEach((line, n) => ctx.fillText(line, x + 18, y + 40 + n * 32));
      ctx.font = `600 24px ${FONT}`;
      ctx.fillStyle = sub;
      ctx.fillText(tile.stateText, x + 18, y + h - 12);
    }
  }

  function update(nextView, nextText, nextKnobs) {
    if (disposed) return;
    view = nextView;
    text = nextText;
    knobStates = nextKnobs;
    dirty = true;
    requestFrame();
  }

  function setTheme(next) {
    if (disposed) return;
    applyTheme(next);
    requestFrame();
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    cancelAnimationFrame(raf);
    raf = 0;
    resizeObserver.disconnect();
    visibilityObserver.disconnect();
    renderer.domElement.remove();
    for (const resource of resources) resource.dispose();
    resources.length = 0;
    renderer.dispose();
  }

  return { update, setTheme, dispose };
}

function canvasTexture(canvas, track) {
  const texture = track(new THREE.CanvasTexture(canvas));
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;
  // Arcs run from right to left as seen from the front, so the texture is flipped to read true.
  texture.wrapS = THREE.RepeatWrapping;
  texture.repeat.x = -1;
  texture.offset.x = 1;
  return texture;
}

/** Splits text into at most `maxLines` lines that fit `maxWidth`; the last line is cut with an ellipsis. */
function wrapLines(ctx, text, maxWidth, maxLines) {
  const words = text.split(' ');
  const lines = [];
  let line = '';
  for (const word of words) {
    const trial = line ? `${line} ${word}` : word;
    if (ctx.measureText(trial).width <= maxWidth || line === '') {
      line = trial;
    } else {
      lines.push(line);
      line = word;
    }
  }
  if (line) lines.push(line);
  if (lines.length > maxLines) {
    lines.length = maxLines;
    lines[maxLines - 1] = `${lines[maxLines - 1]}…`;
  }
  return lines;
}

function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

/** A curved wall piece: part of a cylinder centred on angle `center`, measured from +z. */
function arcGeometry(center, span, radius, bottom, top) {
  return new THREE.CylinderGeometry(radius, radius, top - bottom, 96, 1, true, center - span / 2, span).translate(
    0,
    (top + bottom) / 2,
    0,
  );
}

/** The angle, measured from the front of the console, of knob i out of n. */
function knobArcAngle(i, n) {
  return -CONSOLE_SPAN / 2 + (n === 1 ? 0 : (i / (n - 1)) * CONSOLE_SPAN);
}

/**
 * One physical control on the console. Dials and rotaries show a pointer,
 * switches a lever, pushbuttons a cap that moves down when pressed. Returns
 * place(state), which takes { kind, fraction, travel, depth }.
 */
function makeKnob(group, material, track) {
  const base = new THREE.Mesh(track(new THREE.CylinderGeometry(0.12, 0.12, 0.02, 32)), material.ink);
  base.position.y = 0.01;
  group.add(base);

  const dial = new THREE.Group();
  group.add(dial);
  const body = new THREE.Mesh(track(new THREE.CylinderGeometry(0.075, 0.085, 0.07, 28)), material.steel);
  body.position.y = 0.055;
  dial.add(body);
  const pointer = new THREE.Group();
  pointer.position.y = 0.092;
  dial.add(pointer);
  const mark = new THREE.Mesh(track(new THREE.BoxGeometry(0.014, 0.008, 0.06)), material.ink);
  mark.position.z = 0.035;
  pointer.add(mark);

  const lever = new THREE.Group();
  lever.position.y = 0.02;
  group.add(lever);
  const bar = new THREE.Mesh(track(new THREE.BoxGeometry(0.03, 0.1, 0.03)), material.ink);
  bar.position.y = 0.05;
  lever.add(bar);

  const cap = new THREE.Mesh(track(new THREE.CylinderGeometry(0.065, 0.075, 0.05, 24)), material.accent);
  cap.position.y = 0.035;
  group.add(cap);

  return function place(state) {
    dial.visible = state.kind === 'dial' || state.kind === 'rotary';
    lever.visible = state.kind === 'switch';
    cap.visible = state.kind === 'button';
    if (dial.visible) {
      // The pointer sweeps the same arc as a gauge: from the start stop to the end stop.
      pointer.rotation.y = Math.PI - (state.fraction - 0.5) * KNOB_SWEEP;
    }
    if (lever.visible) lever.rotation.x = (state.travel * 2 - 1) * -0.42;
    if (cap.visible) cap.position.y = 0.035 - state.depth * 0.02;
  };
}
