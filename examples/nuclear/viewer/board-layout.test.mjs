import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ROOM, FLOOR, CEILING_LIGHTS, DEFAULT_VIEW, BOARD, BOARDS, BOARD_PX, DESKS, CCTV, DOOR, STANDING_SPOTS, COLLISIONS, ANNUNCIATOR_WINDOWS, windowState, cellLayout, gapLayout, boardLayout, boardPoint } from './board-layout.mjs';
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
        for (const value of values) assert.ok(value.length * 0.6 * box.font <= box.w, `${value} fits ${name}`);
        assert.ok(box.font <= box.h);
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
  assert.deepEqual(BOARDS.map(b => b.title), ['Reactor board', 'Loops board', 'Turbine board']);
  assert.ok(BOARDS[0].x < BOARDS[1].x && BOARDS[1].x < BOARDS[2].x);
  assert.equal(ROOM.eye, 1.65);
  assert.equal(BOARD.top - BOARD.bottom, 2.2);
  assert.equal(BOARD.deskY, 0.9);
  for (const spot of Object.values(STANDING_SPOTS)) for (const box of COLLISIONS)
    assert.equal(circleHits(spot, ROOM.radius, box), false, spot.name);
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
  const furniture = COLLISIONS.slice(4);
  furniture.forEach((box, i) => {
    assert.ok(box.minX > -ROOM.width / 2 && box.maxX < ROOM.width / 2);
    assert.ok(box.minZ > -ROOM.depth / 2 && box.maxZ < ROOM.depth / 2);
    for (const other of furniture.slice(i + 1))
      assert.ok(box.maxX <= other.minX || other.maxX <= box.minX || box.maxZ <= other.minZ || other.maxZ <= box.minZ);
  });
});

function project(point, spot, width, height) {
  const dx = point.x - spot.x, dy = point.y - ROOM.eye, dz = point.z - spot.z;
  const across = Math.cos(spot.yaw) * dx - Math.sin(spot.yaw) * dz;
  const forward = -Math.sin(spot.yaw) * dx - Math.cos(spot.yaw) * dz;
  const depth = Math.cos(spot.pitch) * forward + Math.sin(spot.pitch) * dy;
  const up = Math.cos(spot.pitch) * dy - Math.sin(spot.pitch) * forward;
  const scale = height / (2 * Math.tan(ROOM.fov * Math.PI / 360) * depth);
  return { x: width / 2 + across * scale, y: height / 2 - up * scale, depth };
}

for (const [width, pageHeight] of [[1440, 900], [1280, 800]]) {
  const height = pageHeight * 0.84;
  const inFrame = (p, margin = 0) => p.depth > 0 && p.x > margin && p.x < width - margin && p.y > margin && p.y < height - margin;
  test(`the establishing view includes desks, boards, floor and lights at ${width} by ${pageHeight}`, () => {
    const spot = STANDING_SPOTS[DEFAULT_VIEW];
    for (const desk of DESKS.filter(d => !d.supervisor)) {
      for (const offset of [-0.51, 0.51]) for (const x of [-0.425, 0.425]) for (const y of [-0.26, 0.26])
        assert.ok(inFrame(project({ x: desk.x + offset + x, y: 1.18 + y, z: desk.z - 0.073 }, spot, width, height), 48));
    }
    for (const board of BOARDS.slice(0, 2)) {
      for (const x of [-BOARD.width / 2, BOARD.width / 2]) for (const y of [BOARD.bottom, BOARD.top])
        assert.ok(inFrame(project(boardPoint(board, x, y, 0), spot, width, height), 48), board.title);
    }
    const floor = project({ x: 2.6, y: 0, z: 2.3 }, spot, width, height);
    assert.ok(inFrame(floor, 24) && floor.y > height * 0.8);
    const visibleLights = CEILING_LIGHTS.xs.flatMap(x => CEILING_LIGHTS.zs.map(z =>
      project({ x, y: ROOM.height - 0.04, z }, spot, width, height))).filter(p => inFrame(p, 48) && p.y < height * 0.3);
    assert.ok(visibleLights.length >= 3);
  });

  test(`each board reading spot keeps meters, the desk, tiles and a ceiling panel in frame at ${width} by ${pageHeight}`, () => {
    for (const board of BOARDS) {
      const spot = STANDING_SPOTS[board.view];
      const top = project(boardPoint(board, 0, BOARD.top, 0), spot, width, height);
      assert.ok(top.y > 64, board.title);
      for (const x of [-BOARD.width / 2, BOARD.width / 2]) for (const y of [BOARD.bottom, BOARD.top])
        assert.ok(inFrame(project(boardPoint(board, x, y, 0), spot, width, height), 48), board.title);
      const desk = project(boardPoint(board, 0, BOARD.deskY, BOARD.deskDepth), spot, width, height);
      assert.ok(desk.y > height * 0.7 && desk.y < height * 0.85, board.title);
      const floor = project(boardPoint(board, 0, 0, 0.15), spot, width, height);
      assert.ok(inFrame(floor, 12) && floor.y > height * 0.9, board.title);
      const seam = project(boardPoint(board, FLOOR.seam, 0, 0.15), spot, width, height);
      assert.ok(seam.x - floor.x >= 4, board.title);
      const light = CEILING_LIGHTS.xs.flatMap(x => CEILING_LIGHTS.zs.map(z =>
        project({ x, y: ROOM.height - 0.04, z }, spot, width, height)))
        .find(p => inFrame(p, 48) && p.y < top.y - 10);
      assert.ok(light, board.title);
      const depth = Math.hypot(spot.x - board.x, spot.z - board.z);
      const scale = height / (2 * Math.tan(ROOM.fov * Math.PI / 360) * depth) * (BOARD.top - BOARD.bottom) / BOARD_PX.height;
      const cell = boardLayout(board.points.length, board.view).cells[0];
      for (const box of Object.values(cellLayout(cell.w, cell.h).text)) assert.ok(box.font * scale >= 11, board.title);
    }
  });

  test(`CCTV and door views include floor and ceiling at ${width} by ${pageHeight}`, () => {
    for (const [name, center, halfWidth, top] of [
      ['cctv', CCTV, CCTV.width / 2, CCTV.y + CCTV.height / 2],
      ['door', DOOR, DOOR.width / 2, DOOR.height],
    ]) {
      const spot = STANDING_SPOTS[name];
      for (const side of [-halfWidth, halfWidth]) {
        const p = { x: center.x + Math.cos(spot.yaw) * side, y: top, z: center.z - Math.sin(spot.yaw) * side };
        assert.ok(inFrame(project(p, spot, width, height), 48), name);
      }
      assert.ok(inFrame(project({ ...center, y: 0 }, spot, width, height), 24), name);
      assert.ok(inFrame(project({ ...center, y: ROOM.height }, spot, width, height), 48), name);
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
  assert.equal(ANNUNCIATOR_WINDOWS.find(w => w.key === 'coolant_flow_low:b').board, 'loops-board');
  assert.equal(ANNUNCIATOR_WINDOWS.find(w => w.key === 'reactor_tripped').board, 'reactor-board');
  for (const board of BOARDS) {
    const layout = boardLayout(board.points.length, board.view);
    for (const [i, window] of layout.windows.entries()) {
      inside(window, BOARD_PX.width, BOARD_PX.height);
      assert.ok(window.legend.length > 0);
      assert.ok(!overlaps(window, layout.header));
      for (const cell of layout.cells) assert.ok(!overlaps(window, cell));
      for (const other of layout.windows.slice(i + 1)) assert.ok(!overlaps(window, other));
      // Two lines reserve enough space for the longest engraved legend.
      const words = window.legend.split(' '); let lines = 1, length = 0;
      for (const word of words) {
        const next = length + (length ? 1 : 0) + word.length;
        if (next * 0.6 * window.font > window.w - 20) { lines++; length = word.length; } else length = next;
      }
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

for (const [width, height] of [[1440, 630], [1280, 560]]) {
  test(`the reactor standing view has readable meters and room around the board at ${width} by ${height}`, () => {
    const board = BOARDS[0], spot = STANDING_SPOTS['reactor-board'];
    const depth = spot.x - board.x;
    const scale = height / (2 * Math.tan(76 * Math.PI / 360) * depth) * (BOARD.top - BOARD.bottom) / BOARD_PX.height;
    const cell = boardLayout(board.points.length, board.view).cells[0];
    const layout = cellLayout(cell.w, cell.h);
    for (const box of Object.values(layout.text)) assert.ok(box.font * scale >= 11);
    for (const dial of layout.dials) assert.ok(dial.radius * scale >= 14);
    assert.ok(BOARD.width / (2 * depth * Math.tan(76 * Math.PI / 360) * width / height) < 0.9);
    assert.ok(BOARD.top < ROOM.eye + depth * Math.tan(76 * Math.PI / 360 + spot.pitch));
    assert.ok(BOARD.deskY > ROOM.eye - (depth - BOARD.deskDepth) * Math.tan(76 * Math.PI / 360 - spot.pitch));
  });
}

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
