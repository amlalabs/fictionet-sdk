import test from 'node:test';
import assert from 'node:assert/strict';
import { RADIUS, BOARD_SPAN, BOARD_BOTTOM, BOARD_TOP, BAND_TOP, BOARD_PX, cellLayout, boardLayout, closeView, overview, closePixelScale, overviewPixelScale } from './board-layout.mjs';

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
  assert.ok(Math.abs(BOARD_PX.height - BOARD_PX.width * (BOARD_TOP - BOARD_BOTTOM) / (RADIUS * BOARD_SPAN)) <= 0.5);
});

for (const aspect of [1.2, 1.6, 2.0]) {
  test(`axis camera fits every face at aspect ${aspect}`, () => {
    for (const center of [Math.PI - BOARD_SPAN, Math.PI, Math.PI + BOARD_SPAN]) {
      const framing = closeView({ center }, aspect);
      assert.deepEqual(framing.eye, [0, (BOARD_TOP + BOARD_BOTTOM) / 2, 0]);
      assert.ok(Math.abs(Math.hypot(framing.look[0], framing.look[2]) - RADIUS) < 1e-9);
      for (let i = 0; i <= 100; i++) {
        const angle = -BOARD_SPAN / 2 + BOARD_SPAN * i / 100;
        const depth = RADIUS * Math.cos(angle);
        const x = Math.abs(RADIUS * Math.sin(angle) / (depth * framing.tanHalfFov * aspect));
        for (const y of [BOARD_BOTTOM, BOARD_TOP]) {
          const projectedY = Math.abs((y - framing.eye[1]) / (depth * framing.tanHalfFov));
          assert.ok(x <= 1 / 1.05 + 1e-9 && projectedY <= 1 / 1.05 + 1e-9);
        }
      }
    }
  });
}

for (const [width, height] of [[750, 470], [660, 376]]) {
  test(`readable close views and visible overview marks at ${width} by ${height}`, (t) => {
    const scale = closePixelScale(width, height);
    for (const count of [6, 9]) {
      const board = boardLayout(count);
      const cell = board.cells[0];
      const layout = cellLayout(cell.w, cell.h);
      const font = Math.min(...Object.values(layout.text).map((box) => box.font), ...Object.values(board.text).map((box) => box.font));
      const radius = Math.min(...layout.dials.map((dial) => dial.radius));
      assert.ok(font * scale >= 11);
      assert.ok(radius * scale >= 14);
      const ring = layout.ringWidth * overviewPixelScale(width, height);
      assert.ok(ring >= 2);
      t.diagnostic(`${count} points: smallest text ${(font * scale).toFixed(2)} CSS px; dial radius ${(radius * scale).toFixed(2)} CSS px; overview ring ${ring.toFixed(2)} CSS px`);
      // Check the smallest local projection scale, including vertical shear.
      const framing = overview(width / height);
      const focal = height / (2 * framing.tanHalfFov);
      for (let i = 0; i <= 120; i++) {
        const angle = -1.5 * BOARD_SPAN + 3 * BOARD_SPAN * i / 120;
        const depth = 3 + RADIUS * Math.cos(angle);
        for (const y of [BOARD_BOTTOM, BOARD_TOP]) {
          const a = (RADIUS + 3 * Math.cos(angle)) / depth ** 2;
          const b = (y - framing.eye[1]) * Math.sin(angle) / depth ** 2;
          const d = 1 / depth;
          const trace = a * a + b * b + d * d;
          const singular = Math.sqrt((trace - Math.sqrt(Math.max(0, trace * trace - 4 * a * a * d * d))) / 2);
          const stroke = singular * focal * (BOARD_TOP - BOARD_BOTTOM) / BOARD_PX.height * layout.ringWidth;
          assert.ok(stroke >= 2);
        }
      }
    }
    const view = overview(width / height);
    const depth = view.eye[2] + RADIUS * Math.cos(1.5 * BOARD_SPAN);
    const occupiedWidth = RADIUS * Math.sin(1.5 * BOARD_SPAN) / (depth * view.tanHalfFov * (width / height));
    const occupiedHeight = (BAND_TOP - BOARD_BOTTOM) / (2 * depth * view.tanHalfFov);
    assert.ok(occupiedWidth >= 0.85 && occupiedWidth <= 1);
    assert.ok(occupiedHeight > 2 / 3 && occupiedHeight <= 1);
    // Include the shelf edges and the full height of each console knob.
    for (const radius of [3.55, 4.1]) {
      for (let i = 0; i <= 76; i++) {
        const angle = (i - 38) * Math.PI / 180;
        const z = view.eye[2] + radius * Math.cos(angle);
        const x = radius * Math.sin(angle) / (z * view.tanHalfFov * width / height);
        for (const y of [0.92, 1.06]) {
          assert.ok(Math.abs(x) < 1 && Math.abs((y - view.eye[1]) / (z * view.tanHalfFov)) < 1);
        }
      }
    }
    t.diagnostic(`Overview fills ${(occupiedWidth * 100).toFixed(1)}% width and ${(occupiedHeight * 100).toFixed(1)}% height`);
  });
}
