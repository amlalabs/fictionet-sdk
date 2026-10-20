import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as THREE from '../../../observe/downloads/vendor/three/build/three.core.js';
import { POINTS } from './instruments.mjs';
import { PALETTE_TOKENS } from './control-room.mjs';
import { createMeters, needleAngle, scaleTicks, heldTag } from './meters.mjs';

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
    assert.equal(ticks.length, 9);
    assert.equal(ticks[0].label, String(range[0]));
    assert.equal(ticks[8].label, String(range[1]));
    assert.equal(ticks.filter(tick => tick.label).length, 5);
    ticks.forEach((tick, i) => {
      assert.equal(tick.value, range[0] + (range[1] - range[0]) * i / 8);
      assert.equal(tick.angle, needleAngle(tick.value, range));
      if (tick.label) assert.equal(Number(tick.label), tick.value);
      if (i) assert.ok(tick.angle < ticks[i - 1].angle);
    });
  }
  assert.deepEqual(scaleTicks([280, 350]).filter(t => t.label).map(t => t.label), ['280', '297.5', '315', '332.5', '350']);
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
    const ctx = {};
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
  for (const name of ['HMI housings', 'PLANT housings', 'HMI bezels', 'PLANT bezels', 'PLANT inlays']) {
    assert.equal(f.mesh(name).count, 21);
    assert.equal(f.mesh(name).isInstancedMesh, true);
  }
  assert.equal(f.mesh('Engraved plates').count, 63);
  assert.equal(f.mesh('Meter needles').count, 42);
  assert.equal(f.mesh('Meter glass').count, 42);
  assert.ok(f.mesh('Meter glass').material.clearcoat > 0);
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
  assert.ok(texts.includes('Lagging -1.7 °C'));
  assert.equal(f.canvases[1].calls.filter(c => c.method === 'fillRect' && c.color === palette.warning).length, 1);
  const a = new THREE.Matrix4(), b = new THREE.Matrix4();
  // The reactor board places this pair second.
  f.mesh('Meter needles').getMatrixAt(2, a); f.mesh('Meter needles').getMatrixAt(3, b);
  const qa = new THREE.Quaternion(), qb = new THREE.Quaternion();
  a.decompose(new THREE.Vector3(), qa, new THREE.Vector3());
  b.decompose(new THREE.Vector3(), qb, new THREE.Vector3());
  assert.ok(qa.angleTo(qb) > 0.3);
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
  f.meters.update(f.pairs, f.shown);
  for (const name of ['Marked HMI rims', 'Marked held rims', 'Marked links']) assert.equal(f.mesh(name).visible, false);
  hot.reported = null;
  f.meters.update(f.pairs, f.shown);
  assert.equal(f.mesh('Meter needles').count, 41);
  f.meters.dispose();
});

test('needle motion never repaints scales or snapshot numbers and theme changes refresh both atlases', () => {
  const f = fixture();
  f.meters.update(f.pairs, f.shown);
  const counts = f.canvases.map(c => c.calls.length);
  const before = new THREE.Matrix4(), after = new THREE.Matrix4();
  f.mesh('Meter needles').getMatrixAt(0, before);
  f.shown.set('hot_leg:a', { reported: 340, truth: 345 });
  f.meters.update(f.pairs, f.shown);
  f.mesh('Meter needles').getMatrixAt(0, after);
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
