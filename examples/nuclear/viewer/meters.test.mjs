import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as THREE from '../../../observe/downloads/vendor/three/build/three.core.js';
import { BOARDS, ROOM, boardLayout, cellLayout, fitSpot } from './board-layout.mjs';
import { POINTS } from './instruments.mjs';
import { PALETTE_TOKENS } from './control-room.mjs';
import { createMeters, paintLetters, needleAngle, scaleTicks, heldTag } from './meters.mjs';

test('needle angles sweep clockwise from the lower left through the top to the lower right', () => {
  for (const { range } of POINTS) {
    const [low, high] = range;
    assert.equal(needleAngle(low, range), -Math.PI * 0.75);
    assert.equal(needleAngle(high, range), -Math.PI * 2.25);
    assert.equal(needleAngle((low + high) / 2, range), -Math.PI * 1.5);
    assert.equal(needleAngle(low - 100, range), needleAngle(low, range));
    assert.equal(needleAngle(high + 100, range), needleAngle(high, range));
    assert.equal(needleAngle(null, range), null);
    assert.equal(needleAngle(undefined, range), null);
    assert.ok(needleAngle(low + (high - low) * 0.7, range) < needleAngle(low + (high - low) * 0.6, range));
  }
});

test('scale ticks print the range endpoints and intermediate values at the needle angles', () => {
  for (const { range } of POINTS) {
    const ticks = scaleTicks(range);
    const labels = ticks.filter(tick => tick.label);
    assert.ok(labels.length >= 2 && labels.length <= 5);
    assert.equal(ticks.length, labels.length * 2 - 1);
    assert.equal(ticks[0].label, String(range[0]));
    assert.equal(ticks.at(-1).label, String(range[1]));
    ticks.forEach((tick, i) => {
      assert.equal(tick.value, range[0] + (range[1] - range[0]) * i / (ticks.length - 1));
      assert.equal(tick.angle, needleAngle(tick.value, range));
      if (tick.label) {
        assert.equal(Number(tick.label), tick.value);
        assert.ok(Number.isInteger(tick.value));
      }
      assert.equal(Boolean(tick.label), i % 2 === 0);
      if (i) assert.ok(tick.angle < ticks[i - 1].angle);
    });
  }
  assert.deepEqual(scaleTicks([260, 350]).filter(t => t.label).map(t => t.label), ['260', '290', '320', '350']);
  assert.deepEqual(scaleTicks([0, 1000]).filter(t => t.label).map(t => t.label), ['0', '250', '500', '750', '1000']);
  assert.deepEqual(scaleTicks([12, 18]).filter(t => t.label).map(t => t.label), ['12', '14', '16', '18']);
});

test('held tags use the snapshot sample time and carry minutes without rounding up', () => {
  assert.equal(heldTag(null), 'HELD');
  assert.equal(heldTag(undefined), 'HELD');
  assert.equal(heldTag(0), 'HELD 0:00.0');
  assert.equal(heldTag(59_999), 'HELD 0:59.9');
  assert.equal(heldTag(60_000), 'HELD 1:00.0');
  assert.equal(heldTag(117_456), 'HELD 1:57.4');
  assert.equal(heldTag(3_600_100), 'HELD 60:00.1');
});

const css = readFileSync(new URL('./viewer.css', import.meta.url), 'utf8');
const tokens = Object.fromEntries([...css.match(/:root\s*\{([^}]+)\}/)[1].matchAll(/(--[\w-]+):\s*(#[\da-f]+);/g)].map(([, name, color]) => [name, color]));
const palette = Object.fromEntries(Object.entries(PALETTE_TOKENS).map(([name, token]) => [name, tokens[token]]));

function fixture() {
  const canvases = [];
  const makeCanvas = () => {
    const calls = [];
    const ctx = { measureText: value => ({ width: value.length * 5 }) };
    for (const method of ['save', 'restore', 'translate', 'scale', 'fillRect', 'fillText', 'strokeRect', 'beginPath', 'moveTo', 'lineTo', 'stroke']) {
      ctx[method] = (...args) => calls.push({ method, args, color: ctx.fillStyle });
    }
    const canvas = { getContext: () => ctx, calls };
    canvases.push(canvas);
    return canvas;
  };
  const scene = new THREE.Scene();
  const meters = createMeters(THREE, scene, palette, { makeCanvas });
  const pairs = POINTS.map(p => ({
    key: p.key, label: p.label, range: p.range, unit: p.unit,
    reported: (p.range[0] + p.range[1]) / 2, trueValue: (p.range[0] + p.range[1]) / 2,
    gap: 0, marked: false, diverged: false, frozen: false, sampledAtMs: 117_400,
  }));
  const shown = new Map(pairs.map(p => [p.key, { reported: p.reported, truth: p.trueValue }]));
  const mesh = name => scene.getObjectByName(name);
  return { scene, meters, pairs, shown, canvases, mesh };
}

test('all pairs use physical rims, needles, glass and plates with a small fixed batch count', (t) => {
  const f = fixture();
  f.meters.update(f.pairs, f.shown);
  for (const name of ['HMI bezels', 'PLANT bezels', 'PLANT inlays']) {
    assert.equal(f.mesh(name).count, 21);
    assert.equal(f.mesh(name).isInstancedMesh, true);
  }
  for (const name of ['HMI bezels', 'PLANT bezels']) {
    const mesh = f.mesh(name);
    assert.equal(mesh.geometry.index.count / 3, 96);
    for (let i = 0; i < mesh.count; i++) {
      const matrix = new THREE.Matrix4();
      mesh.getMatrixAt(i, matrix);
      const scale = new THREE.Vector3().setFromMatrixScale(matrix);
      mesh.geometry.computeBoundingBox();
      assert.ok(Math.abs(mesh.geometry.boundingBox.min.z * scale.z + 0.061) < 1e-7);
      assert.ok(Math.abs(mesh.geometry.boundingBox.max.z) < 1e-7);
    }
  }
  assert.equal(f.mesh('Engraved plates').count, 63);
  assert.equal(f.mesh('Meter needles').count, 42);
  assert.equal(f.mesh('Meter glass').count, 42);
  assert.equal(f.mesh('Meter glass').material.clearcoat, 0);
  assert.ok(f.mesh('Meter glass').material.roughness >= 0.8);
  assert.equal(f.mesh('HMI bezels').material.color.getHexString(), palette.rubber.slice(1));
  assert.ok(f.mesh('PLANT bezels').material.metalness > 0.5);
  for (const name of ['Marked HMI rims', 'Marked links', 'Marked held rims', 'Held rims']) assert.equal(f.mesh(name).visible, false);
  for (const pair of f.pairs) { pair.marked = true; pair.frozen = true; }
  f.meters.update(f.pairs, f.shown);
  let calls = 0, triangles = 0;
  f.scene.traverse(object => {
    if (!object.isMesh || !object.visible || object.count === 0) return;
    calls++;
    triangles += (object.geometry.index?.count ?? object.geometry.attributes.position.count) / 3 * (object.isInstancedMesh ? object.count : 1);
    assert.equal(object.castShadow, false);
  });
  assert.ok(calls <= 16, `${calls} meter batches`);
  assert.ok(triangles < 20_000, `${triangles} meter triangles`);
  t.diagnostic(`All pairs held and marked: ${calls} meter batches, ${triangles} triangles.`);
  f.pairs[0].frozen = false;
  f.pairs[1].marked = false;
  f.meters.update(f.pairs, f.shown);
  const batches = f.scene.children[0].children.filter(mesh => mesh.visible && mesh.count !== 0).length;
  assert.ok(batches <= 16, `${batches} meter batches with mixed states`);
  t.diagnostic(`Mixed meter states: ${batches} batches.`);
  f.meters.dispose();
});

test('only marked pairs get amber and frozen rims remain dashed without inventing a warning', () => {
  const f = fixture();
  const hot = f.pairs.find(p => p.key === 'hot_leg:b');
  const lag = f.pairs.find(p => p.key === 'hot_leg:a');
  hot.marked = true; hot.diverged = true; hot.gap = -5.4; hot.reported = 325; hot.trueValue = 330.4;
  lag.diverged = true; lag.gap = -1.7;
  f.shown.set(hot.key, { reported: hot.reported, truth: hot.trueValue });
  f.meters.update(f.pairs, f.shown);
  assert.equal(f.mesh('Marked HMI rims').count, 1);
  assert.equal(f.mesh('Marked links').count, 1);
  const texts = f.canvases[1].calls.filter(c => c.method === 'fillText').map(c => c.args[0]);
  assert.ok(texts.includes('▲ Gap -5.4 °C'));
  for (const [index, key] of BOARDS.flatMap(board => board.points).entries()) {
    const expected = key === hot.key ? '▲ Gap -5.4 °C' : '';
    assert.equal(texts[index * 4 + 2], expected, `${key} gap line`);
  }
  assert.ok(f.canvases[1].calls.some(c => c.method === 'fillText' && c.args[0] === '▲ Gap -5.4 °C' && c.color === palette.surface));
  assert.equal(f.canvases[1].calls.filter(c => c.method === 'fillRect' && c.color === palette.warning).length, 1);
  const a = new THREE.Matrix4(), b = new THREE.Matrix4();
  const index = BOARDS.flatMap(board => board.points).indexOf(hot.key) * 2;
  f.mesh('Meter needles').getMatrixAt(index, a);
  f.mesh('Meter needles').getMatrixAt(index + 1, b);
  const qa = new THREE.Quaternion(), qb = new THREE.Quaternion();
  a.decompose(new THREE.Vector3(), qa, new THREE.Vector3());
  b.decompose(new THREE.Vector3(), qb, new THREE.Vector3());
  const expectedAngle = Math.abs(needleAngle(hot.reported, hot.range) - needleAngle(hot.trueValue, hot.range));
  assert.ok(Math.abs(qa.angleTo(qb) - expectedAngle) < 1e-6);
  hot.frozen = true; lag.frozen = true;
  f.meters.update(f.pairs, f.shown);
  assert.equal(f.mesh('Marked HMI rims').count, 0);
  assert.equal(f.mesh('Marked held rims').count, 16);
  assert.equal(f.mesh('Held rims').count, 16);
  assert.ok(f.canvases[1].calls.some(c => c.method === 'fillText' && c.args[0] === 'HELD 1:57.4'));
  hot.sampledAtMs = null;
  f.meters.update(f.pairs, f.shown);
  assert.ok(f.canvases[1].calls.some(c => c.method === 'fillText' && c.args[0] === 'HELD'));
  hot.marked = false;
  f.canvases[1].calls.length = 0;
  f.meters.update(f.pairs, f.shown);
  assert.equal(f.canvases[1].calls.filter(c => c.method === 'fillText')[2].args[0], '');
  for (const name of ['Marked HMI rims', 'Marked held rims', 'Marked links']) assert.equal(f.mesh(name).visible, false);
  hot.reported = null;
  f.canvases[1].calls.length = 0;
  f.meters.update(f.pairs, f.shown);
  assert.equal(f.mesh('Meter needles').count, 41);
  const gapLine = f.canvases[1].calls.filter(c => c.method === 'fillText')[2];
  assert.equal(gapLine.args[0], 'No reading');
  assert.equal(gapLine.color, palette.ink);
  f.meters.dispose();
});

test('a missing reported value keeps the gap line in normal ink even when marked', () => {
  const f = fixture();
  const pair = f.pairs.find(p => p.key === 'hot_leg:b');
  pair.reported = null;
  pair.marked = true;
  f.meters.update(f.pairs, f.shown);
  const index = BOARDS.flatMap(board => board.points).indexOf(pair.key);
  const gapLine = f.canvases[1].calls.filter(c => c.method === 'fillText')[index * 4 + 2];
  assert.equal(gapLine.args[0], 'No reading');
  assert.equal(gapLine.color, palette.ink);
  assert.equal(f.canvases[1].calls.some(c => c.method === 'fillRect' && c.color === palette.warning), false);
  f.meters.dispose();
});

test('needle motion never repaints scales or snapshot numbers and theme changes refresh both atlases', () => {
  const f = fixture();
  f.meters.update(f.pairs, f.shown);
  const counts = f.canvases.map(c => c.calls.length);
  const before = new THREE.Matrix4(), after = new THREE.Matrix4();
  const index = BOARDS.flatMap(board => board.points).indexOf('hot_leg:a') * 2;
  f.mesh('Meter needles').getMatrixAt(index, before);
  f.shown.set('hot_leg:a', { reported: 340, truth: 345 });
  f.meters.update(f.pairs, f.shown);
  f.mesh('Meter needles').getMatrixAt(index, after);
  assert.notDeepEqual(before.elements, after.elements);
  assert.deepEqual(f.canvases.map(c => c.calls.length), counts);
  const pair = f.pairs.find(p => p.key === 'hot_leg:a');
  pair.reported = 341;
  f.meters.update(f.pairs, f.shown);
  assert.equal(f.canvases[0].calls.length, counts[0]);
  assert.ok(f.canvases[1].calls.some(c => c.method === 'fillText' && c.args[0] === '341.0 °C'));
  pair.range = [200, 400];
  f.meters.update(f.pairs, f.shown);
  assert.ok(f.canvases[0].calls.length > counts[0]);
  const changed = f.canvases.map(c => c.calls.length);
  f.meters.setTheme({ ...palette, ink: palette.text });
  f.meters.update(f.pairs, f.shown);
  f.canvases.forEach((c, i) => assert.ok(c.calls.length > changed[i]));
  f.meters.dispose();
});

test('disposing meters frees the textures, materials, geometry and instance buffers', () => {
  const f = fixture();
  const resources = new Set();
  f.scene.traverse(object => {
    if (!object.isMesh) return;
    resources.add(object.geometry); resources.add(object.material);
    if (object.isInstancedMesh) resources.add(object);
    if (object.material.map) resources.add(object.material.map);
  });
  const disposed = new Set();
  resources.forEach(resource => resource.addEventListener('dispose', () => disposed.add(resource)));
  f.meters.dispose();
  assert.equal(f.scene.children.length, 0);
  assert.deepEqual(disposed, resources);
  f.meters.dispose();
});


test('printed lettering fills its reserved ink height and stays centered', () => {
  for (const [ascent, descent] of [[26, 0], [24, 8], [0, 0]]) {
    const calls = [];
    const ctx = { measureText: () => ({ actualBoundingBoxAscent: ascent, actualBoundingBoxDescent: descent }) };
    for (const method of ['save', 'restore', 'translate', 'scale', 'fillText']) {
      ctx[method] = (...args) => calls.push({ method, args });
    }
    const box = { x: 10, y: 20, w: 200, h: 40, font: 37, stretch: 0.85 };
    paintLetters(ctx, 'Lagging -1.9 °C', box, palette.ink);
    const scale = calls.find(call => call.method === 'scale').args;
    assert.equal(scale[0], 0.85);
    assert.equal(scale[1] * (ascent + descent || box.font), box.font);
    assert.deepEqual(calls.find(call => call.method === 'translate').args, [110, 40]);
    assert.equal(calls.find(call => call.method === 'fillText').args[2], (ascent - descent) / 2);
    assert.equal(calls.find(call => call.method === 'fillText').args.length, 3);
    assert.equal(ctx.textBaseline, 'alphabetic');
    assert.equal(ctx.fillStyle, palette.ink);
  }
});


test('the merged printed meshes preserve readable lettering at every fitted spot', t => {
  const f = fixture();
  const scales = f.mesh('Printed scales and plates').geometry.attributes.position;
  const readouts = f.mesh('Snapshot readouts').geometry.attributes.position;
  const circleVertices = f.mesh('Meter glass').geometry.index.count;
  for (const [width, height] of [[785, 491], [692, 433]]) {
    const camera = new THREE.PerspectiveCamera(ROOM.fov, width / height, 0.05, 100);
    let index = 0;
    let smallestLabel = Infinity;
    let smallestValue = Infinity;
    let smallestRadius = Infinity;
    for (const board of BOARDS) {
      const spot = fitSpot(board, width / height);
      camera.position.set(spot.x, ROOM.eye, spot.z);
      camera.rotation.set(spot.pitch, spot.yaw, 0, 'YXZ');
      camera.updateMatrixWorld(true);
      const letterHeight = (positions, offset, box) => {
        const ys = Array.from({ length: 6 }, (_, vertex) => new THREE.Vector3()
          .fromBufferAttribute(positions, offset + vertex).project(camera).y);
        return (Math.max(...ys) - Math.min(...ys)) * height / 2 * box.font / box.h;
      };
      for (const cell of boardLayout(board.points.length, board.view).cells) {
        const layout = cellLayout(cell.w, cell.h);
        for (const [slot, box] of [layout.text.label, layout.text.hmi, layout.text.plant].entries()) {
          const pixels = letterHeight(scales, index * (18 + 2 * circleVertices) + slot * 6, box);
          assert.ok(pixels >= 10, `${board.id} label ${pixels}`);
          smallestLabel = Math.min(smallestLabel, pixels);
        }
        for (const [slot, box] of [layout.text.reported, layout.text.truth, layout.gapLine, layout.text.held].entries()) {
          const pixels = letterHeight(readouts, index * 24 + slot * 6, box);
          assert.ok(pixels >= 11, `${board.id} value ${pixels}`);
          smallestValue = Math.min(smallestValue, pixels);
        }
        for (const name of ['HMI bezels', 'PLANT bezels']) {
          const matrix = new THREE.Matrix4();
          f.mesh(name).getMatrixAt(index, matrix);
          const center = new THREE.Vector3().applyMatrix4(matrix).project(camera);
          const edge = new THREE.Vector3(1, 0, 0).applyMatrix4(matrix).project(camera);
          const radius = Math.abs(edge.x - center.x) * width / 2;
          assert.ok(radius >= 20, `${board.id} dial ${radius}`);
          smallestRadius = Math.min(smallestRadius, radius);
        }
        index++;
      }
    }
    assert.equal(index, POINTS.length);
    t.diagnostic(`${width} by ${height}: merged label ${smallestLabel.toFixed(3)} px, value ${smallestValue.toFixed(3)} px, radius ${smallestRadius.toFixed(3)} px.`);
  }
  f.meters.dispose();
});
