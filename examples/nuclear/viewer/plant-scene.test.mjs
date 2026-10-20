import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { readFileSync } from 'node:fs';
import * as THREE from '../../../observe/downloads/vendor/three/build/three.module.js';
import { PALETTE_TOKENS } from './control-room.mjs';

const hook = registerHooks({
  resolve(specifier, context, next) {
    if (specifier === '/vendor/three/build/three.module.js')
      return { url: new URL('../../../observe/downloads/vendor/three/build/three.module.js', import.meta.url).href, shortCircuit: true };
    return next(specifier, context);
  },
});
const { createPlantScene, VIEWS } = await import('./plant-scene.mjs');
hook.deregister();
const css = readFileSync(new URL('./viewer.css', import.meta.url), 'utf8');
const tokens = Object.fromEntries([...css.match(/:root\s*\{([^}]+)\}/)[1].matchAll(/(--[\w-]+):\s*(#[\da-f]+);/g)].map(([, key, value]) => [key, value]));
const theme = Object.fromEntries(Object.entries(PALETTE_TOKENS).map(([key, token]) => [key, tokens[token]]));

function snapshot() {
  return {
    at_ms: 1000, revision: 1, operator_actions: 0,
    telemetry: { quiet: false, heartbeat: 1, last_sample_ms: 1000 },
    reported_status: {}, readings: [], alarms: [], faults: { process: [] },
    truth: {
      reactor: { neutron_power_percent: 100, control_rod_percent: 80, shutdown_rod_percent_inserted: 0, core_exit_c: 325, trip: null },
      primary: {
        pressure_mpa: 15.5, level_percent: 55, heaters_on: false, spray_percent: 0, relief_open: false,
        loops: [0, 1].map(() => ({ hot_leg_c: 325, cold_leg_c: 290, flow_percent: 100, pump_running: true, pump_speed_percent: 100 })),
      },
      secondary: {
        loops: [0, 1].map(() => ({ steam_kg_s: 400, feed_kg_s: 400, level_percent: 50, feed_valve_percent: 60 })),
        feed_pumps_running: [true, true], steam_pressure_mpa: 6.9, turbine_valve_percent: 90,
        turbine_tripped: false, generator_mw: 600, condenser_pressure_kpa: 5,
        circulating_water_running: true, steam_dump_percent: 0, steam_relief_open: false,
      },
    },
  };
}

function fixture(t, reduced = false) {
  const text = [];
  const ctx = {
    fillRect() {}, save() {}, restore() {}, translate() {}, scale() {},
    beginPath() {}, moveTo() {}, lineTo() {}, stroke() {},
    fillText(value) { text.push(value); },
  };
  const previous = globalThis.document;
  globalThis.document = { createElement: () => ({ width: 0, height: 0, getContext: () => ctx }) };
  const plant = createPlantScene({ theme, reducedMotion: () => reduced, environment: null });
  t.after(() => {
    plant.dispose();
    if (previous === undefined) delete globalThis.document;
    else globalThis.document = previous;
  });
  return { plant, text };
}
const at = (mesh, i = 0) => {
  const matrix = new THREE.Matrix4();
  mesh.getMatrixAt(i, matrix);
  return new THREE.Vector3().setFromMatrixPosition(matrix);
};
const named = (plant, name) => {
  const object = plant.scene.getObjectByName(name);
  assert.ok(object, name);
  return object;
};

test('the scene contract and standing cameras keep containment on CCTV', t => {
  const { plant } = fixture(t);
  assert.deepEqual(Object.keys(plant).sort(), ['scene', 'camera', 'cctvCamera', 'advance', 'setView', 'update', 'setTheme', 'dispose'].sort());
  for (const view of ['reactor', 'turbine', 'overview']) {
    plant.setView(view);
    assert.deepEqual(plant.camera.position.toArray(), VIEWS[view].eye);
    assert.equal(plant.camera.position.y, 1.7);
  }
  plant.setView('turbine');
  const fan = named(plant, 'Pump B fan');
  assert.equal(fan.layers.test(plant.cctvCamera.layers), true);
  assert.equal(fan.layers.test(plant.camera.layers), false);
  assert.throws(() => plant.setView('missing'));
  plant.scene.updateMatrixWorld(true);
  plant.cctvCamera.updateMatrixWorld(true);
  const projected = fan.getWorldPosition(new THREE.Vector3()).project(plant.cctvCamera);
  assert.ok(Math.abs(projected.x) < 0.8 && Math.abs(projected.y) < 0.8 && projected.z < 1);
});

test('standing views frame the equipment and overhead structure, with an open view into the condenser well', t => {
  const { plant } = fixture(t);
  plant.update(snapshot());
  plant.scene.updateMatrixWorld(true);
  for (const [view, points] of [
    ['reactor', [[0, 2.6, -2], [-4.5, 6.7, -5], [4.5, 6.7, -5], [3.7, 1.45, 1.9], [0, 7.75, -2.5]]],
    ['turbine', [[32.5, 1.4, -0.7], [46.4, 1.4, -0.7], [38.3, -1.3, 2.5], [40, 7.4, -7]]],
  ]) {
    plant.setView(view);
    // The canvas sizes the page measures at 1440x900 and 1280x800.
    for (const [width, height] of [[785, 491], [692, 433]]) {
      plant.camera.aspect = width / height;
      plant.camera.updateProjectionMatrix(); plant.camera.updateMatrixWorld(true);
      for (const point of points) {
        const p = new THREE.Vector3(...point).project(plant.camera);
        assert.ok(Math.abs(p.x) < 1 && Math.abs(p.y) < 1 && p.z < 1, `${view} at ${width}x${height}: ${point} in frame`);
      }
    }
  }
  const target = new THREE.Vector3(38.3, -1.3, 2.5);
  const direction = target.clone().sub(plant.camera.position);
  const ray = new THREE.Raycaster(plant.camera.position, direction.clone().normalize(), 0, direction.length() - 0.05);
  ray.layers.mask = plant.camera.layers.mask;
  assert.deepEqual(ray.intersectObjects(plant.scene.children, true), []);
});

test('a stopped pump motor coasts at snapshot speed while the other pump keeps turning', t => {
  const { plant } = fixture(t), snap = snapshot();
  plant.update(snap);
  const a = named(plant, 'Pump A fan'), b = named(plant, 'Pump B fan');
  plant.advance(0.1);
  const start = b.rotation.z, startA = a.rotation.z;
  snap.truth.primary.loops[1].pump_running = false;
  snap.truth.primary.loops[1].pump_speed_percent = 60;
  plant.update(snap); plant.advance(0.1);
  const fast = Math.abs(b.rotation.z - start);
  assert.ok(Math.abs(fast - 0.54) < 1e-9);
  assert.ok(Math.abs(a.rotation.z - startA + 0.9) < 1e-9);
  snap.truth.primary.loops[1].pump_speed_percent = 15;
  plant.update(snap);
  const middle = b.rotation.z;
  plant.advance(0.1);
  assert.ok(Math.abs(b.rotation.z - middle) < fast / 3);
  snap.truth.primary.loops[1].pump_speed_percent = 0;
  plant.update(snap);
  const end = b.rotation.z;
  plant.advance(0.25);
  assert.equal(b.rotation.z, end);
});

test('rod stems and collars drop and position lights follow true rod insertion', t => {
  const { plant } = fixture(t), snap = snapshot();
  plant.update(snap);
  const rods = named(plant, 'Rod stems'), collars = named(plant, 'Rod position collars');
  const before = [at(rods, 0).y, at(rods, 20).y, at(collars, 0).y];
  snap.truth.reactor.control_rod_percent = 0;
  snap.truth.reactor.shutdown_rod_percent_inserted = 100;
  snap.truth.reactor.trip = { cause: 'manual' };
  plant.update(snap);
  for (let i = 0; i < 12; i++) plant.advance(0.25);
  assert.ok(at(rods, 0).y < before[0] - 1.2);
  assert.ok(at(rods, 20).y < before[1] - 1.5);
  assert.ok(at(collars, 0).y < before[2] - 1.2);
  const matrix = new THREE.Matrix4();
  named(plant, 'Rod lights on').getMatrixAt(4, matrix);
  assert.equal(new THREE.Vector3().setFromMatrixScale(matrix).length(), 0);
  named(plant, 'Rod lights off').getMatrixAt(4, matrix);
  assert.ok(new THREE.Vector3().setFromMatrixScale(matrix).length() > 0);
});

test('field gauges ignore reported faults and show exact truth values', async t => {
  const { plant, text } = fixture(t), snap = snapshot();
  snap.truth.primary.loops[1].hot_leg_c = 338.2;
  snap.readings = [{ sensor: { hot_leg: 'b' }, reading: { value: 301.1 }, fault: 'quiet' }];
  plant.update(snap);
  assert.ok(text.includes('338.2 °C'));
  assert.ok(!text.includes('301.1 °C'));
  const needles = named(plant, 'Field gauge needles');
  const matrix = new THREE.Matrix4();
  needles.getMatrixAt(1, matrix);
  const angle = Math.atan2(matrix.elements[1], matrix.elements[0]);
  const { POINTS } = await import('./instruments.mjs');
  const [low, high] = POINTS.find(point => point.key === 'hot_leg:b').range;
  const expected = Math.PI * 0.75 - Math.PI * 1.5 * ((338.2 - low) / (high - low));
  assert.ok(Math.abs(angle - expected) < 1e-6);
  assert.equal(text.some(value => /reported|gap|diverged/i.test(value)), false);
});

test('steam, spray and roof exhaust stay animated without a running shaft or pumps', t => {
  const { plant } = fixture(t), snap = snapshot();
  snap.truth.primary.loops.forEach(loop => { loop.pump_speed_percent = 0; });
  snap.truth.secondary.generator_mw = 0; snap.truth.secondary.turbine_tripped = true;
  snap.truth.primary.spray_percent = 40;
  snap.truth.primary.relief_open = true;
  snap.truth.secondary.steam_dump_percent = 30;
  plant.update(snap);
  for (const name of ['Pressurizer spray', 'Pressurizer relief', 'Roof vent plume', 'Main steam flow'])
    assert.equal(named(plant, name).visible, true);
  const steam = named(plant, 'Main steam flow'), before = at(steam).clone();
  assert.equal(plant.advance(0.1), true);
  assert.ok(at(steam).distanceTo(before) > 0);
  snap.truth.primary.spray_percent = 0; snap.truth.primary.relief_open = false;
  snap.truth.secondary.steam_dump_percent = 0;
  snap.truth.secondary.loops.forEach(loop => { loop.steam_kg_s = 0; });
  plant.update(snap);
  for (const name of ['Pressurizer spray', 'Pressurizer relief', 'Roof vent plume', 'Main steam flow'])
    assert.equal(named(plant, name).visible, false);
  snap.truth.secondary.steam_relief_open = true;
  plant.update(snap);
  assert.equal(named(plant, 'Roof vent plume').visible, true);
  assert.equal(plant.advance(0.1), true);
});

test('reduced motion freezes rotation and camera, and snaps rods, gauges and levels', t => {
  const { plant } = fixture(t, true), snap = snapshot();
  plant.update(snap);
  const camera = plant.camera.position.clone(), fan = named(plant, 'Pump B fan');
  const shaft = named(plant, 'Turbine generator shaft');
  const angle = fan.rotation.z, shaftAngle = shaft.rotation.x;
  snap.truth.reactor.control_rod_percent = 0;
  snap.truth.reactor.shutdown_rod_percent_inserted = 100;
  snap.truth.primary.level_percent = 10;
  plant.update(snap);
  assert.equal(plant.advance(0.25), false);
  assert.equal(fan.rotation.z, angle); assert.equal(shaft.rotation.x, shaftAngle);
  assert.ok(plant.camera.position.equals(camera));
  assert.ok(Math.abs(at(named(plant, 'Rod stems')).y - 1.45) < 1e-6);
  const fills = [];
  plant.scene.traverse(o => { if (o.isMesh && o.userData.animated && o.geometry.attributes.position.count === 24) fills.push(o); });
  assert.ok(fills.some(o => Math.abs(o.scale.y - 0.35) < 1e-9));
});

test('walking uses the shared canvas, stops at equipment and releases input on disposal', t => {
  const { plant } = fixture(t);
  plant.update(snapshot());
  const frames = new Map(), host = { dataset: { view: 'Reactor building' } };
  let serial = 0, renders = 0;
  const previous = { window: globalThis.window, requestAnimationFrame: globalThis.requestAnimationFrame, cancelAnimationFrame: globalThis.cancelAnimationFrame };
  globalThis.window = new EventTarget();
  globalThis.requestAnimationFrame = callback => { frames.set(++serial, callback); return serial; };
  globalThis.cancelAnimationFrame = id => frames.delete(id);
  t.after(() => { Object.assign(globalThis, previous); });
  const canvas = new EventTarget();
  canvas.closest = () => host;
  canvas.focus = () => {};
  const renderer = { domElement: canvas, info: { reset() {} }, render(scene, camera) { assert.equal(scene, plant.scene); assert.equal(camera, plant.camera); renders++; } };
  plant.scene.onBeforeRender(renderer);
  const key = (type, code) => canvas.dispatchEvent(Object.assign(new Event(type, { cancelable: true }), { code }));
  const tick = now => { const pending = [...frames.values()]; frames.clear(); pending.forEach(callback => callback(now)); };
  key('keydown', 'KeyW');
  const start = plant.camera.position.z;
  const now = performance.now();
  for (let i = 1; i <= 200; i++) tick(now + i * 50);
  assert.ok(plant.camera.position.z < start - 4);
  assert.ok(plant.camera.position.z >= 0.33 - 1e-8);
  assert.equal(plant.camera.position.y, 1.7);
  assert.ok(renders > 0);
  host.dataset.view = 'Control room';
  const held = plant.camera.position.clone();
  tick(now + 11000);
  assert.ok(plant.camera.position.equals(held));
  plant.dispose();
  host.dataset.view = 'Reactor building';
  key('keydown', 'KeyW');
  assert.equal(frames.size, 0);
});

test('both interiors fit the budget even without frustum culling and release scene resources', t => {
  const { plant } = fixture(t), snap = snapshot();
  plant.update(snap);
  const geometry = new Set(), materials = new Set(), textures = new Set();
  for (const view of ['reactor', 'turbine']) {
    plant.setView(view);
    let calls = 0, triangles = 0;
    plant.scene.traverse(object => {
      if (!object.isMesh) return;
      geometry.add(object.geometry); materials.add(object.material);
      if (object.material.map) textures.add(object.material.map);
      if (!object.layers.test(plant.camera.layers)) return;
      const passes = object.material.transparent && object.material.side === THREE.DoubleSide ? 2 : 1;
      calls += passes;
      triangles += (object.geometry.index?.count ?? object.geometry.attributes.position.count) / 3 * (object.count ?? 1) * passes;
    });
    assert.ok(calls < 150, `${view}: ${calls} calls`);
    assert.ok(triangles < 300000, `${view}: ${triangles} triangles`);
    t.diagnostic(`${view}: at most ${calls} calls and ${triangles} triangles; all meshes counted`);
  }
  plant.scene.traverse(object => { if (object.isLight) assert.equal(object.castShadow, false); });
  let freed = 0;
  for (const resource of [...geometry, ...materials, ...textures]) resource.addEventListener('dispose', () => { freed++; });
  plant.dispose();
  assert.equal(freed, geometry.size + materials.size + textures.size);
  assert.equal(plant.scene.children.length, 0);
});
