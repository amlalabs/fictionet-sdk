import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ROOM, FLOOR, CEILING_LIGHTS, DEFAULT_VIEW, BOARD, BOARDS, BOARD_PX, DESKS, CHAIRS, CCTV, DOOR,
  STANDING_SPOTS, COLLISIONS, ANNUNCIATOR_WINDOWS, HORSESHOE_CENTER, windowState, cellLayout, gapLayout,
  boardLayout, boardPoint, fitSpot, devicePlacements, meterCenter, deskOutline, mimicLines } from './board-layout.mjs';
import { KNOBS } from './control-room.mjs';
import { POINTS } from './instruments.mjs';
import { circleHits } from './room-motion.mjs';

const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
const inside = (box, width, height) => {
  assert.ok(box.x >= 0 && box.y >= 0);
  assert.ok(box.x + box.w <= width + 1e-9);
  assert.ok(box.y + box.h <= height + 1e-9);
};
const strings = {
  label: ['Pressurizer pressure', 'Core exit temperature', 'Steam gen. level A'],
  hmi: ['HMI'], plant: ['Plant'],
  reported: ['15.57 MPa', '599.6 MW', '563.9 kg/s', 'no reading'],
  truth: ['15.57 MPa', '599.6 MW', '563.9 kg/s', 'no reading'],
  gap: ['Gap -10.9 °C', 'Lagging +1.9 °C', 'No instrument'],
  held: ['Held at 3:21.3'],
};

for (const count of [6, 9]) {
  test(`${count} point board reserves separate space for every line and dial`, () => {
    const board = boardLayout(count);
    inside(board.header, BOARD_PX.width, BOARD_PX.height);
    for (const cell of board.cells) {
      inside(cell, BOARD_PX.width, BOARD_PX.height);
      assert.ok(!overlaps(board.header, cell));
      const layout = cellLayout(cell.w, cell.h);
      const texts = Object.values(layout.text);
      for (const box of [...texts, ...layout.dials, layout.warning]) inside(box, cell.w, cell.h);
      for (let i = 0; i < texts.length; i++) {
        for (let j = i + 1; j < texts.length; j++) assert.ok(!overlaps(texts[i], texts[j]));
        for (const dial of layout.dials) assert.ok(!overlaps(texts[i], dial));
        assert.ok(!overlaps(texts[i], layout.warning));
      }
      for (const [name, values] of Object.entries(strings)) {
        const box = layout.text[name];
        for (const value of values) assert.ok(value.length * 0.6 * box.font * box.stretch <= box.w, `${value} fits ${name}`);
        assert.ok(box.font <= box.h);
        assert.ok(box.stretch >= 0.85);
      }
    }
    const headerTexts = Object.values(board.text);
    headerTexts.forEach((box, i) => {
      inside(box, board.header.w, board.header.h);
      headerTexts.slice(i + 1).forEach((other) => assert.ok(!overlaps(box, other)));
    });
    for (const [name, value] of Object.entries({ title: 'Reactor controls', time: 'Plant time 3:21.3', telemetry: 'Telemetry live, heartbeat 1234567890' })) {
      assert.ok(value.length * 0.6 * board.text[name].font <= board.text[name].w);
    }
  });
}

test('canvas texels have equal physical width and height within pixel rounding', () => {
  assert.ok(Math.abs(BOARD_PX.height - BOARD_PX.width * (BOARD.top - BOARD.bottom) / BOARD.width) <= 0.5);
});

test('boards form a horseshoe at human scale with clear standing spots', () => {
  assert.deepEqual(BOARDS.map(b => b.id), ['rps', 'rcs', 'loops', 'feed', 'turbine']);
  assert.equal(BOARDS.length, 5);
  assert.equal(BOARDS.reduce((sum, board) => sum + board.width, 0), 14);
  assert.equal(ROOM.eye, 1.65);
  assert.equal(BOARD.top - BOARD.bottom, 2.2);
  assert.equal(BOARD.deskY, 0.9);
  for (const [index, board] of BOARDS.entries()) {
    const towardCenter = Math.atan2(HORSESHOE_CENTER.x - board.x, HORSESHOE_CENTER.z - board.z);
    assert.ok(Math.abs(towardCenter - board.yaw) < 10 * Math.PI / 180, board.id);
    const next = BOARDS[index + 1];
    if (next) {
      assert.ok(board.yaw > next.yaw);
      const right = boardPoint(board, board.width / 2, 0, 0);
      const left = boardPoint(next, -next.width / 2, 0, 0);
      assert.ok(Math.hypot(right.x - left.x, right.z - left.z) < 0.05, `${board.id} joins ${next.id}`);
      const a = deskOutline(board)[2];
      const b = deskOutline(next)[3];
      const deskRight = boardPoint(board, a.x, 0, a.z);
      const deskLeft = boardPoint(next, b.x, 0, b.z);
      assert.ok(Math.hypot(deskRight.x - deskLeft.x, deskRight.z - deskLeft.z) < 0.001, 'mitered desk joins');
    }
    for (const x of [-board.width / 2, board.width / 2]) {
      const rear = boardPoint(board, x, 0, -0.2);
      assert.ok(ROOM.width / 2 - 0.12 - Math.abs(rear.x) >= 0.9, `${board.id} side service aisle`);
      assert.ok(ROOM.depth / 2 - 0.12 - Math.abs(rear.z) >= 0.9, `${board.id} rear service aisle`);
    }
  }
  assert.deepEqual(BOARDS.flatMap(b => b.points).sort(), POINTS.map(p => p.key).sort());
  for (const spot of Object.values(STANDING_SPOTS)) for (const box of COLLISIONS) {
    assert.equal(circleHits(spot, ROOM.radius, box), false, spot.name);
  }
});

test('the control room is the first standing spot and every spot clears the room and furniture', () => {
  assert.equal(DEFAULT_VIEW, 'control-room');
  assert.equal(Object.keys(STANDING_SPOTS)[0], DEFAULT_VIEW);
  assert.equal(STANDING_SPOTS[DEFAULT_VIEW].name, 'Control room');
  for (const spot of Object.values(STANDING_SPOTS)) {
    assert.ok(Math.abs(spot.x) + ROOM.radius < ROOM.width / 2, spot.name);
    assert.ok(Math.abs(spot.z) + ROOM.radius < ROOM.depth / 2, spot.name);
    for (const box of COLLISIONS) assert.equal(circleHits(spot, ROOM.radius, box), false, spot.name);
  }
  const supervisor = DESKS.find(d => d.supervisor);
  assert.ok(Math.hypot(STANDING_SPOTS[DEFAULT_VIEW].x - supervisor.x, STANDING_SPOTS[DEFAULT_VIEW].z - supervisor.z) < 3);
});

test('board faces and furniture reserve separate footprints', () => {
  for (const board of BOARDS) {
    const { header, windows, cells } = boardLayout(board.points.length, board.view);
    const boxes = [header, ...windows, ...cells];
    boxes.forEach((box, i) => {
      inside(box, BOARD_PX.width, BOARD_PX.height);
      for (const other of boxes.slice(i + 1)) assert.ok(!overlaps(box, other), board.title);
    });
  }
  const furniture = [...DESKS.map(d => ({ x: d.x - d.w / 2, y: d.z - d.d / 2, w: d.w, h: d.d })),
    ...CHAIRS.map(c => ({ x: c.x - 0.3, y: c.z - 0.3, w: 0.6, h: 0.6 }))];
  const bench = COLLISIONS.slice(4, 4 + BOARDS.length * 14);
  for (const [index, piece] of furniture.entries()) {
    assert.ok(Math.abs(piece.x) < ROOM.width / 2 && Math.abs(piece.x + piece.w) < ROOM.width / 2);
    assert.ok(Math.abs(piece.y) < ROOM.depth / 2 && Math.abs(piece.y + piece.h) < ROOM.depth / 2);
    for (const other of furniture.slice(index + 1)) assert.ok(!overlaps(piece, other));
    for (const box of bench) {
      assert.ok(!overlaps(piece, { x: box.minX, y: box.minZ, w: box.maxX - box.minX, h: box.maxZ - box.minZ }));
    }
  }
});

function project(point, spot, width, height) {
  const dx = point.x - spot.x, dy = point.y - ROOM.eye, dz = point.z - spot.z;
  const across = Math.cos(spot.yaw) * dx - Math.sin(spot.yaw) * dz;
  const forward = -Math.sin(spot.yaw) * dx - Math.cos(spot.yaw) * dz;
  const depth = Math.cos(spot.pitch) * forward + Math.sin(spot.pitch) * dy;
  const up = Math.cos(spot.pitch) * dy - Math.sin(spot.pitch) * forward;
  const scale = height / (2 * Math.tan(spot.fov * Math.PI / 360) * depth);
  return { x: width / 2 + across * scale, y: height / 2 - up * scale, depth };
}

// Measured hero columns at page sizes 1440 by 900 and 1280 by 800, with the stage at sixteen by ten.
const CANVASES = [[785, 491], [692, 433]];
for (const [width, height] of CANVASES) {
  const inFrame = (p, margin = 0.04) => p.depth > 0 && p.x >= width * margin && p.x <= width * (1 - margin)
    && p.y >= height * margin && p.y <= height * (1 - margin);
  test(`the establishing view shows the U and desks below a limited ceiling at ${width} by ${height}`, t => {
    const spot = STANDING_SPOTS[DEFAULT_VIEW];
    const edges = [];
    for (const board of BOARDS.slice(1, 4)) {
      for (const x of [-BOARD.width / 2, BOARD.width / 2]) for (const y of [BOARD.bottom, BOARD.top]) {
        const corner = project(boardPoint(board, x, y, 0), spot, width, height);
        edges.push(corner.x);
        assert.ok(inFrame(corner), board.title);
      }
    }
    for (const board of [BOARDS[0], BOARDS.at(-1)]) {
      let left = 0;
      let right = 1;
      for (const y of [BOARD.bottom, BOARD.top]) {
        const ends = [-BOARD.width / 2, BOARD.width / 2].map(x =>
          project(boardPoint(board, x, y, 0), spot, width, height));
        edges.push(...ends.map(p => p.x));
        assert.ok(ends.every(p => p.depth > 0), board.title);
        // Clip in homogeneous coordinates to measure physical panel width.
        for (const distance of [
          p => p.x * p.depth, p => (width - p.x) * p.depth,
          p => p.y * p.depth, p => (height - p.y) * p.depth,
        ]) {
          const [a, b] = ends.map(distance);
          assert.ok(a >= 0 || b >= 0, `${board.title} intersects the frame`);
          if (a < 0) left = Math.max(left, -a / (b - a));
          if (b < 0) right = Math.min(right, a / (a - b));
        }
      }
      const share = Math.max(0, right - left);
      // The closest pose that keeps the ceiling under a fifth of the frame crops the outer segments a little.
      assert.ok(share >= 0.55, `${board.title} shows at least fifty-five percent of its full-height width`);
      t.diagnostic(`${board.title} visible width ${(share * 100).toFixed(2)}%.`);
    }
    const span = (Math.max(...edges) - Math.min(...edges)) / width;
    assert.ok(span >= 0.85);
    t.diagnostic(`U width ${(span * 100).toFixed(2)}% of the frame.`);
    for (const box of COLLISIONS) assert.equal(circleHits(spot, ROOM.radius, box), false, spot.name);
    for (const desk of DESKS.filter(d => !d.supervisor)) {
      assert.ok(desk.z < spot.z);
      const end = deskOutline(BOARDS[0])[3];
      const opening = boardPoint(BOARDS[0], end.x, 0, end.z);
      assert.ok(desk.z + desk.d / 2 < opening.z, 'operator desks stay inside the U');
      for (const x of [-desk.w / 2, desk.w / 2]) for (const z of [-desk.d / 2, desk.d / 2]) {
        for (const y of [0, 0.823]) {
          assert.ok(inFrame(project({ x: desk.x + x, y, z: desk.z + z }, spot, width, height)));
        }
      }
      for (const offset of [-0.51, 0.51]) for (const x of [-0.455, 0.455])
        for (const y of [-0.295, 0.295]) for (const z of [-0.18, -0.08]) {
          assert.ok(inFrame(project({ x: desk.x + offset + x, y: 1.18 + y, z: desk.z + z }, spot, width, height)));
        }
      for (const offset of [-0.51, 0.51]) for (const x of [-0.425, 0.425]) for (const y of [-0.26, 0.26]) {
        const p = { x: desk.x + offset + x, y: 1.18 + y, z: desk.z - 0.073 };
        assert.ok(inFrame(project(p, spot, width, height)));
      }
    }
    assert.ok(DESKS.find(d => d.supervisor).z > spot.z);
    for (const chair of CHAIRS) assert.ok(chair.z - 0.3 > spot.z, 'chairs stay behind the eye');
    for (const x of [-BOARD.width / 2, BOARD.width / 2]) {
      assert.ok(boardPoint(BOARDS[2], x, BOARD.bottom, 0).z < spot.z, 'the center segment stays ahead of the eye');
    }
    const lights = CEILING_LIGHTS.xs.flatMap(x => CEILING_LIGHTS.zs.map(z =>
      project({ x, y: ROOM.height - 0.04, z }, spot, width, height)));
    assert.ok(lights.some(p => inFrame(p, 0) && p.y < height * 0.2));
  });

  test(`each fitted section includes edges, headers, desks and every nameplate at ${width} by ${height}`, () => {
    const placements = devicePlacements(KNOBS);
    for (const board of BOARDS) {
      const spot = { ...STANDING_SPOTS[board.view], ...fitSpot(board, width / height, STANDING_SPOTS[board.view].fov) };
      assert.ok(!COLLISIONS.some(box => circleHits(spot, ROOM.radius, box)), board.id);
      for (const x of [-BOARD.width / 2, BOARD.width / 2]) for (const y of [BOARD.bottom, BOARD.top]) {
        assert.ok(inFrame(project(boardPoint(board, x, y, 0), spot, width, height)), board.title);
      }
      for (const x of [-BOARD.width / 2, BOARD.width / 2]) {
        const edge = boardPoint(board, x, BOARD.deskY - Math.sin(BOARD.slope) * BOARD.deskDepth - 0.06, BOARD.deskDepth);
        assert.ok(inFrame(project(edge, spot, width, height)), `${board.id} desk`);
      }
      const layout = boardLayout(board.points.length, board.view);
      const boxes = [...Object.values(layout.text), ...layout.cells.flatMap(cell => {
        return Object.values(cellLayout(cell.w, cell.h).text).map(box => ({ ...box, x: box.x + cell.x, y: box.y + cell.y }));
      })];
      for (const box of boxes) for (const x of [box.x, box.x + box.w]) for (const y of [box.y, box.y + box.h]) {
        const point = boardPoint(board, x / BOARD_PX.width * BOARD.width - BOARD.width / 2,
          BOARD.top - y / BOARD_PX.height * (BOARD.top - BOARD.bottom), 0.06);
        assert.ok(inFrame(project(point, spot, width, height)), `${board.id} printed text`);
      }
      for (const device of placements.filter(p => p.segment === board.id)) {
        for (const x of [-0.075, 0.075]) for (const y of [-0.02, 0.02]) {
          const point = boardPoint(board, device.x + x, BOARD.deskY + 0.09 + y, BOARD.deskDepth / 4 + 0.08);
          assert.ok(inFrame(project(point, spot, width, height)), device.id);
        }
      }
    }
  });

  test(`every fitted segment has readable meter lettering and dials at ${width} by ${height}`, t => {
    let smallestLetter = Infinity;
    let smallestReadout = Infinity;
    let smallestRadius = Infinity;
    for (const board of BOARDS) {
      const spot = { ...STANDING_SPOTS[board.view], ...fitSpot(board, width / height, STANDING_SPOTS[board.view].fov) };
      const layout = boardLayout(board.points.length, board.view);
      const projected = (x, y, z) => project(boardPoint(board,
        x / BOARD_PX.width * BOARD.width - BOARD.width / 2,
        BOARD.top - y / BOARD_PX.height * (BOARD.top - BOARD.bottom), z), spot, width, height);
      const lettering = (box, minimum, z) => {
        const top = projected(box.x, box.y + (box.h - box.font) / 2, z);
        const bottom = projected(box.x, box.y + (box.h + box.font) / 2, z);
        const pixels = Math.abs(bottom.y - top.y);
        assert.ok(pixels >= minimum, `${board.id}: ${pixels.toFixed(3)} px below ${minimum}`);
        smallestLetter = Math.min(smallestLetter, pixels);
        if (minimum === 11) smallestReadout = Math.min(smallestReadout, pixels);
      };
      Object.values(layout.text).forEach(box => lettering(box, 10, 0.031));
      for (const cell of layout.cells) {
        const meter = cellLayout(cell.w, cell.h);
        for (const [name, box] of Object.entries(meter.text)) {
          const readout = ['reported', 'truth', 'gap', 'held'].includes(name);
          lettering({ ...box, x: cell.x + box.x, y: cell.y + box.y }, readout ? 11 : 10, readout ? 0.04 : 0.058);
        }
        for (const dial of meter.dials) {
          const center = projected(cell.x + dial.x + dial.radius, cell.y + dial.y + dial.radius, 0.086);
          const edge = projected(cell.x + dial.x, cell.y + dial.y + dial.radius, 0.086);
          const pixels = Math.abs(center.x - edge.x);
          assert.ok(pixels >= 20, `${board.id}: dial radius ${pixels.toFixed(3)} px`);
          smallestRadius = Math.min(smallestRadius, pixels);
        }
      }
    }
    t.diagnostic(`Smallest lettering ${smallestLetter.toFixed(3)} px; readout ${smallestReadout.toFixed(3)} px; dial radius ${smallestRadius.toFixed(3)} px.`);
  });

  test(`CCTV and door views include floor and ceiling at ${width} by ${height}`, () => {
    for (const [name, center, halfWidth, top] of [
      ['cctv', CCTV, CCTV.width / 2, CCTV.y + CCTV.height / 2],
      ['door', DOOR, DOOR.width / 2, DOOR.height],
    ]) {
      const spot = STANDING_SPOTS[name];
      for (const side of [-halfWidth, halfWidth]) {
        const p = { x: center.x + Math.cos(spot.yaw) * side, y: top, z: center.z - Math.sin(spot.yaw) * side };
        assert.ok(inFrame(project(p, spot, width, height)), name);
      }
      assert.ok(inFrame(project({ ...center, y: 0 }, spot, width, height)), name);
      assert.ok(inFrame(project({ ...center, y: ROOM.height }, spot, width, height)), name);
    }
  });
}

test('every alarm in the plant has exactly one permanent window on its board', () => {
  const rust = readFileSync(new URL('../world/src/protection.rs', import.meta.url), 'utf8');
  const all = rust.match(/pub const ALL: \[Self; ALARM_COUNT\] = \[([\s\S]*?)\];/)[1];
  const expected = [...all.matchAll(/Self::(\w+)(?:\(Loop::([AB])\))?/g)].map(([, name, loop]) =>
    name.replace(/[A-Z]/g, (c, i) => `${i ? '_' : ''}${c.toLowerCase()}`) + (loop ? `:${loop.toLowerCase()}` : ''));
  const keys = ANNUNCIATOR_WINDOWS.map(w => w.key);
  assert.equal(keys.length, 22); assert.equal(new Set(keys).size, 22);
  assert.deepEqual([...keys].sort(), expected.sort());
  assert.deepEqual(ANNUNCIATOR_WINDOWS.filter(w => w.board === 'turbine-board').map(w => w.key), ['turbine_tripped', 'condenser_vacuum_low']);
  assert.equal(ANNUNCIATOR_WINDOWS.find(w => w.key === 'coolant_flow_low:b').board, 'rcs-board');
  assert.equal(ANNUNCIATOR_WINDOWS.find(w => w.key === 'reactor_tripped').board, 'rps-board');
  for (const board of BOARDS) {
    const layout = boardLayout(board.points.length, board.view);
    for (const [i, window] of layout.windows.entries()) {
      inside(window, BOARD_PX.width, BOARD_PX.height);
      assert.ok(window.legend.length > 0);
      assert.ok(!overlaps(window, layout.header));
      for (const cell of layout.cells) assert.ok(!overlaps(window, cell));
      for (const other of layout.windows.slice(i + 1)) assert.ok(!overlaps(window, other));
      // The near square windows reserve up to three lines for the engraved legend.
      const words = window.engraved.split(' ');
      let lines = 1;
      let length = 0;
      for (const word of words) {
        const next = length + (length ? 1 : 0) + word.length;
        if (next * 0.6 * window.font > window.w - 8) {
          lines++;
          length = word.length;
        } else {
          length = next;
        }
      }
      assert.ok(lines <= 3, window.legend);
      assert.ok(lines * window.font <= window.h, window.legend);
    }
  }
});

test('alarm windows flash twice a second only while unacknowledged', () => {
  for (const t of [0, 125, 249, 500, 749, 1000]) assert.deepEqual(windowState('active', t), { lit: true, mark: false });
  for (const t of [250, 499, 750, 999]) assert.deepEqual(windowState('active', t), { lit: false, mark: false });
  for (const t of [0, 250, 500, 750]) {
    assert.deepEqual(windowState('normal', t), { lit: false, mark: false });
    assert.deepEqual(windowState(undefined, t), { lit: false, mark: false });
    assert.deepEqual(windowState('acknowledged', t), { lit: true, mark: false });
    assert.deepEqual(windowState('active', t, true), { lit: true, mark: true });
    assert.deepEqual(windowState('normal', t, true), { lit: false, mark: false });
    assert.deepEqual(windowState('acknowledged', t, true), { lit: true, mark: false });
  }
});

test('every control sits under its own meter without overlapping another device', () => {
  const knobs = KNOBS.filter(k => k.group === 'plant');
  const placements = devicePlacements(KNOBS);
  assert.equal(placements.length, knobs.length);
  for (const knob of knobs) {
    const p = placements.find(p => p.id === knob.id);
    const board = BOARDS.find(b => b.id === knob.board);
    assert.equal(p.segment, knob.board);
    assert.equal(p.yaw, board.yaw);
    if (knob.point === null) {
      assert.equal(knob.id, 'acknowledge');
      assert.equal(board.id, 'loops');
      assert.ok(Math.abs(p.x) < 0.5);
    } else {
      assert.ok(board.points.includes(knob.point), knob.id);
      assert.ok(Math.abs(p.x - meterCenter(board, knob.point)) < 0.3, knob.id);
    }
    const y = BOARD.deskY - Math.sin(BOARD.slope) * BOARD.deskDepth / 4;
    assert.deepEqual(p.position, boardPoint(board, p.x, y, BOARD.deskDepth / 4));
    const depth = Math.sin(board.yaw) * (p.position.x - board.x) + Math.cos(board.yaw) * (p.position.z - board.z);
    assert.ok(depth > 0 && depth <= BOARD.deskDepth / 3);
    assert.ok(p.footprint.y >= 0 && p.footprint.y + p.footprint.h <= BOARD.deskDepth);
    assert.ok(p.footprint.x >= -BOARD.width / 2 && p.footprint.x + p.footprint.w <= BOARD.width / 2);
    for (const other of placements.filter(q => q.segment === p.segment && q.id !== p.id)) {
      assert.ok(!overlaps(p.footprint, other.footprint), `${p.id} and ${other.id}`);
    }
  }
  assert.deepEqual(devicePlacements([...KNOBS].reverse()).map(p => p.segment).sort(), placements.map(p => p.segment).sort());
});

test('fit distance follows canvas aspect and camera field of view', () => {
  const board = BOARDS[2];
  assert.ok(fitSpot(board, 1.2).distance > fitSpot(board, 1.6).distance);
  assert.ok(fitSpot(board, 1.2).distance > fitSpot(board, 2).distance);
  assert.equal(fitSpot(board, 1.6).distance, fitSpot(board, 2).distance);
  assert.ok(fitSpot(board, 1.6, 60).distance > fitSpot(board, 1.6, 76).distance);
  assert.throws(() => fitSpot(board, 0), RangeError);
});

for (const count of [6, 9]) {
  test(`${count} point board centers the warning and longest gap text without overlap`, () => {
    const cell = boardLayout(count).cells[0];
    const { gapLine } = cellLayout(cell.w, cell.h);
    const longest = strings.gap.reduce((a, b) => a.length > b.length ? a : b);
    const gap = gapLayout(gapLine, longest.length * 0.6 * gapLine.font);
    assert.ok(!overlaps(gap.warning, gap.text));
    assert.equal(gap.text.x - (gap.warning.x + gap.warning.w), 6);
    for (const box of [gap.warning, gap.text]) {
      assert.ok(box.x >= gapLine.x);
      assert.ok(box.x + box.w <= gapLine.x + gapLine.w);
      assert.equal(box.y, gapLine.y);
      assert.equal(box.h, gapLine.h);
    }
    assert.ok(Math.abs((gap.warning.x + gap.text.x + gap.text.w) / 2 - cell.w / 2) < 1e-9);
  });
}


test('hot and cold mimic paths stay in the meter rows and meet across segment joins', () => {
  assert.deepEqual(mimicLines(BOARDS[0]), []);
  assert.deepEqual(mimicLines(BOARDS[4]), []);
  for (const board of BOARDS.slice(1, 4)) {
    const lines = mimicLines(board);
    assert.equal(lines.length, 4);
    for (const line of lines) {
      const y = BOARD.top - line.y * BOARD.width / BOARD_PX.width;
      assert.ok(y >= 1.15 && y <= 2.35);
      assert.ok(line.start >= 0 && line.end <= BOARD_PX.width && line.start < line.end);
      assert.equal(line.direction, line.color === 'hotCoolant' ? 1 : -1);
      const point = board.points.findIndex(key => key.endsWith(`:${line.loop}`));
      const cell = boardLayout(board.points.length, board.view).cells[point];
      const dial = cellLayout(cell.w, cell.h).dials[0];
      assert.ok(line.y > cell.y + dial.y && line.y < cell.y + dial.y + dial.h);
    }
  }
  for (let i = 1; i < 3; i++) {
    const a = BOARDS[i];
    const b = BOARDS[i + 1];
    for (const [index, left] of mimicLines(a).entries()) {
      const right = mimicLines(b)[index];
      assert.equal(left.y, right.y);
      assert.equal(left.end, BOARD_PX.width);
      assert.equal(right.start, 0);
      const p = boardPoint(a, BOARD.width / 2, BOARD.top - left.y * BOARD.width / BOARD_PX.width, 0);
      const q = boardPoint(b, -BOARD.width / 2, BOARD.top - right.y * BOARD.width / BOARD_PX.width, 0);
      assert.ok(Math.hypot(p.x - q.x, p.y - q.y, p.z - q.z) < 0.001);
    }
  }
});

test('standing spots own their field of view and keep section optics unchanged', () => {
  assert.ok(STANDING_SPOTS[DEFAULT_VIEW].fov >= 50);
  assert.ok(STANDING_SPOTS[DEFAULT_VIEW].fov <= 62);
  for (const board of BOARDS) assert.equal(STANDING_SPOTS[board.view].fov, 76);
  for (const spot of Object.values(STANDING_SPOTS)) {
    assert.ok(Number.isFinite(spot.fov) && spot.fov > 0 && spot.fov < 180);
  }
});

test('the plant door opens through the rear wall while both jambs still block walking', () => {
  const start = STANDING_SPOTS.door;
  for (const z of [6.8, 7, 7.2]) {
    assert.equal(COLLISIONS.some(box => circleHits({ x: start.x, z }, ROOM.radius, box)), false);
  }
  for (const x of [3.7, 5.3]) {
    assert.equal(COLLISIONS.some(box => circleHits({ x, z: 7 }, ROOM.radius, box)), true);
  }
});
