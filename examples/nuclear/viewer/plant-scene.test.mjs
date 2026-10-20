import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { readFileSync } from 'node:fs';
import * as THREE from '../../../observe/downloads/vendor/three/build/three.module.js';
import { PLANT_OFFSETS, DOORWAYS, ROOM, STANDING_SPOTS, COLLISIONS } from './board-layout.mjs';
import { walk, walkDelta, doorwayCrossing, circleHits } from './room-motion.mjs';
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
  const plates = [];
  const scales = [];
  const ctx = {
    createRadialGradient() { return { addColorStop() {} }; },
    drawImage(canvas) { plates.push(canvas); },
    fillRect() {}, save() {}, restore() {}, translate() {},
    scale(...args) { scales.push(args); },
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
  return { plant, text, plates, scales };
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
  assert.deepEqual(Object.keys(plant).sort(), ['scene', 'camera', 'cctvCamera', 'obstacles', 'advance', 'setView', 'update', 'setTheme', 'dispose'].sort());
  for (const view of ['reactor', 'turbine', 'overview']) {
    plant.setView(view);
    assert.deepEqual(plant.camera.position.toArray(), VIEWS[view].eye);
    assert.equal(plant.camera.position.y, 1.7);
  }
  plant.setView('turbine');
  const fan = named(plant, 'Pump B coupling');
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
    ['reactor', [[0, 2.6, -2], [-4.5, 6.7, -5], [4.5, 6.7, -5], [3.7, 1.45, 1.9], [3.7, 4.09, 1.3], [-4.5, 6.95, -5], [4.5, 6.95, -5], [0, 7.75, -2.5]]],
    ['turbine', [[32.5, 1.4, -0.7], [46.4, 1.4, -0.7], [38.3, -1.3, 2.5], [40, 7.4, -7]]],
  ]) {
    plant.setView(view);
    // The canvas sizes the page measures at 1440x900 and 1280x800.
    for (const [width, height] of [[785, 491], [692, 433]]) {
      plant.camera.aspect = width / height;
      plant.camera.updateProjectionMatrix(); plant.camera.updateMatrixWorld(true);
      for (const point of points) {
        const offset = PLANT_OFFSETS[view];
        const p = new THREE.Vector3(point[0] + offset.x, point[1], point[2] + offset.z).project(plant.camera);
        assert.ok(Math.abs(p.x) < 1 && Math.abs(p.y) < 1 && p.z < 1, `${view} at ${width}x${height}: ${point} in frame`);
      }
    }
  }
  const target = new THREE.Vector3(38.3 + PLANT_OFFSETS.turbine.x, -1.3, 2.5 + PLANT_OFFSETS.turbine.z);
  const direction = target.clone().sub(plant.camera.position);
  const ray = new THREE.Raycaster(plant.camera.position, direction.clone().normalize(), 0, direction.length() - 0.05);
  ray.camera = plant.camera;
  ray.layers.mask = plant.camera.layers.mask;
  assert.deepEqual(ray.intersectObjects(plant.scene.children, true), []);
});

test('a stopped pump motor coasts at snapshot speed while the other pump keeps turning', t => {
  const { plant } = fixture(t), snap = snapshot();
  plant.update(snap);
  const a = named(plant, 'Pump A coupling'), b = named(plant, 'Pump B coupling');
  plant.advance(0.1);
  const start = b.rotation.y, startA = a.rotation.y;
  snap.truth.primary.loops[1].pump_running = false;
  snap.truth.primary.loops[1].pump_speed_percent = 60;
  plant.update(snap); plant.advance(0.1);
  const fast = Math.abs(b.rotation.y - start);
  assert.ok(Math.abs(fast - 0.54) < 1e-9);
  assert.ok(Math.abs(a.rotation.y - startA + 0.9) < 1e-9);
  const couplings = named(plant, 'Pump couplings');
  const stripes = named(plant, 'Pump coupling stripes');
  assert.equal(couplings.count, 2);
  assert.equal(stripes.count, 2);
  for (const [i, rotor] of [a, b].entries()) {
    const matrix = new THREE.Matrix4();
    couplings.getMatrixAt(i, matrix);
    assert.ok(Math.abs(matrix.elements[8] / 0.43 - Math.sin(rotor.rotation.y)) < 1e-7);
    const mark = at(stripes, i);
    assert.ok(Math.abs(mark.x - rotor.position.x - Math.sin(rotor.rotation.y) * 0.43) < 1e-6);
    assert.ok(Math.abs(mark.z - rotor.position.z - Math.cos(rotor.rotation.y) * 0.43) < 1e-6);
  }
  snap.truth.primary.loops[1].pump_speed_percent = 15;
  plant.update(snap);
  const middle = b.rotation.y;
  plant.advance(0.1);
  assert.ok(Math.abs(b.rotation.y - middle) < fast / 3);
  snap.truth.primary.loops[1].pump_speed_percent = 0;
  plant.update(snap);
  const end = b.rotation.y;
  plant.advance(0.25);
  assert.equal(b.rotation.y, end);
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
  const lights = named(plant, 'Rod position lights');
  assert.equal(lights.count, 105);
  lights.getMatrixAt(4, matrix);
  assert.ok(new THREE.Vector3().setFromMatrixScale(matrix).length() > 0);
  const color = new THREE.Color();
  lights.getColorAt(4, color);
  assert.equal(color.getHexString(), theme.lampOff.slice(1));
  assert.equal(lights.geometry.attributes.instanceGlow.getX(4), 0);
  lights.getColorAt(0, color);
  assert.equal(color.getHexString(), theme.lampGlow.slice(1));
  assert.equal(lights.geometry.attributes.instanceGlow.getX(0), 1);
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
  for (const name of ['Pressurizer spray', 'Pressurizer relief', 'Roof vent plume'])
    assert.equal(named(plant, name).visible, true);
  assert.equal(plant.scene.getObjectByName('Main steam flow'), undefined);
  const plume = named(plant, 'Roof vent plume');
  const before = plume.children[0].position.clone();
  assert.equal(plant.advance(0.1), true);
  assert.ok(plume.children[0].position.distanceTo(before) > 0);
  assert.ok(plume.children.every(particle => particle.isSprite));
  snap.truth.primary.spray_percent = 0; snap.truth.primary.relief_open = false;
  snap.truth.secondary.steam_dump_percent = 0;
  snap.truth.secondary.loops.forEach(loop => { loop.steam_kg_s = 0; });
  plant.update(snap);
  for (const name of ['Pressurizer spray', 'Pressurizer relief', 'Roof vent plume'])
    assert.equal(named(plant, name).visible, false);
  snap.truth.secondary.steam_relief_open = true;
  plant.update(snap);
  assert.equal(named(plant, 'Roof vent plume').visible, true);
  assert.equal(plant.advance(0.1), true);
});

test('reduced motion freezes rotation and camera, and snaps rods, gauges and levels', t => {
  const { plant } = fixture(t, true), snap = snapshot();
  plant.update(snap);
  const camera = plant.camera.position.clone(), fan = named(plant, 'Pump B coupling');
  const shaft = named(plant, 'Turbine generator shaft');
  const angle = fan.rotation.y, shaftAngle = shaft.rotation.x;
  snap.truth.reactor.control_rod_percent = 0;
  snap.truth.reactor.shutdown_rod_percent_inserted = 100;
  snap.truth.primary.level_percent = 10;
  plant.update(snap);
  assert.equal(plant.advance(0.25), false);
  assert.equal(fan.rotation.y, angle); assert.equal(shaft.rotation.x, shaftAngle);
  assert.ok(plant.camera.position.equals(camera));
  assert.ok(Math.abs(at(named(plant, 'Rod stems')).y - 1.45) < 1e-6);
  const fills = named(plant, 'Sight glass levels');
  assert.equal(fills.count, 3);
  const matrix = new THREE.Matrix4();
  fills.getMatrixAt(2, matrix);
  assert.equal(new THREE.Vector3().setFromMatrixScale(matrix).y, Math.fround(0.35));
});

test('the plant registers no input listeners or render callbacks and disposal leaves the canvas alone', t => {
  const previous = globalThis.window;
  const listeners = new Set();
  let registrations = 0;
  const target = () => ({
    addEventListener(type, callback) {
      registrations++;
      listeners.add(callback);
    },
    removeEventListener(type, callback) { listeners.delete(callback); },
  });
  globalThis.window = target();
  t.after(() => {
    if (previous === undefined) delete globalThis.window;
    else globalThis.window = previous;
  });
  const { plant } = fixture(t);
  const canvas = target();
  let renders = 0;
  const renderer = { domElement: canvas, render() { renders++; } };
  plant.update(snapshot());
  for (const view of ['reactor', 'turbine']) {
    plant.setView(view);
    plant.scene.onBeforeRender(renderer);
    plant.advance(0.1);
  }
  assert.equal(listeners.size, 0);
  assert.equal(renders, 0);
  assert.equal(registrations, 0);
  plant.dispose();
  assert.equal(listeners.size, 0);
});

test('holding forward crosses the corridor, hall and personnel airlock with a continuous pose', t => {
  const { plant } = fixture(t);
  let pose = { ...STANDING_SPOTS.door };
  let space = 'control-room';
  const visited = [space];
  const boxes = { 'control-room': COLLISIONS, ...plant.obstacles };
  const keys = new Set(['KeyW']);
  for (let step = 0; step < 400 && pose.z < 35; step++) {
    const previous = pose;
    const delta = walkDelta(keys, pose.yaw, 0.1);
    pose = walk(pose, delta.x, delta.z, boxes[space], ROOM.radius);
    const next = doorwayCrossing(space, previous, pose, DOORWAYS, ROOM.radius);
    assert.ok(Math.abs(pose.x - STANDING_SPOTS.door.x) < 1e-10);
    assert.ok(Math.abs(pose.z - previous.z - delta.z) < 1e-10);
    assert.equal(pose.yaw, previous.yaw);
    assert.equal(pose.fov, previous.fov);
    assert.ok(!boxes[next].some(box => circleHits(pose, ROOM.radius, box)));
    if (next !== space) visited.push(next);
    space = next;
  }
  assert.deepEqual(visited, ['control-room', 'corridor', 'turbine', 'airlock', 'reactor']);
  assert.ok(pose.z >= 35);
  pose.yaw = 0;
  for (let step = 0; step < 400 && pose.z > 4; step++) {
    const previous = pose;
    const delta = walkDelta(keys, pose.yaw, 0.1);
    pose = walk(pose, delta.x, delta.z, boxes[space], ROOM.radius);
    space = doorwayCrossing(space, previous, pose, DOORWAYS, ROOM.radius);
  }
  assert.equal(space, 'control-room');
  assert.ok(pose.z <= 4);
});

test('both interiors fit the budget even without frustum culling and release scene resources', t => {
  const { plant } = fixture(t), snap = snapshot();
  plant.update(snap);
  const geometry = new Set(), materials = new Set(), textures = new Set();
  for (const view of ['reactor', 'turbine']) {
    plant.setView(view);
    let calls = 0, triangles = 0;
    plant.scene.traverse(object => {
      if (!object.isMesh && !object.isSprite) return;
      if (object.isMesh) geometry.add(object.geometry);
      materials.add(object.material);
      if (object.material.map) textures.add(object.material.map);
      if (!object.layers.test(plant.camera.layers)) return;
      const passes = object.material.transparent && object.material.side === THREE.DoubleSide && !object.material.forceSinglePass ? 2 : 1;
      calls += passes;
      if (object.isSprite) triangles += 2;
      else triangles += (object.geometry.index?.count ?? object.geometry.attributes.position.count) / 3 * (object.count ?? 1) * passes;
    });
    assert.ok(calls < 60, `${view}: ${calls} calls`);
    assert.ok(triangles < 40000, `${view}: ${triangles} triangles`);
    t.diagnostic(`${view}: at most ${calls} calls and ${triangles} triangles; all meshes counted`);
  }
  plant.scene.traverse(object => { if (object.isLight) assert.equal(object.castShadow, false); });
  let freed = 0;
  for (const resource of [...geometry, ...materials, ...textures]) resource.addEventListener('dispose', () => { freed++; });
  plant.dispose();
  assert.equal(freed, geometry.size + materials.size + textures.size);
  assert.equal(plant.scene.children.length, 0);
});

test('plates keep their aspect inside mipmapped atlases and gauges stay at field scale', t => {
  const { plant, plates, scales, text } = fixture(t);
  plant.update(snapshot());
  assert.deepEqual(scales, []);
  assert.equal(text.some(value => value.includes('WASD')), false);
  const unique = [...new Set(plates)];
  assert.ok(unique.some(canvas => canvas.width === 512 && canvas.height === 512));
  assert.ok(unique.some(canvas => Math.abs(canvas.width / canvas.height - 7 / 0.65) < 0.01));
  const atlases = new Set();
  plant.scene.traverse(object => {
    if (object.material?.isMeshBasicMaterial) atlases.add(object.material.map);
    if (object.name !== 'Field gauge cases') return;
    const matrix = new THREE.Matrix4();
    for (let i = 0; i < object.count; i++) {
      object.getMatrixAt(i, matrix);
      const scale = new THREE.Vector3().setFromMatrixScale(matrix);
      assert.ok(scale.x * 2 >= 0.2 && scale.x * 2 <= 0.3);
    }
  });
  assert.equal(atlases.size, 2);
  for (const atlas of atlases) {
    assert.equal(atlas.generateMipmaps, true);
    assert.equal(atlas.minFilter, THREE.LinearMipmapLinearFilter);
    assert.equal(atlas.anisotropy, 4);
  }
});

test('vertical pump motors, guards and steam drums occupy their equipment envelopes', t => {
  const { plant } = fixture(t);
  plant.update(snapshot());
  plant.scene.updateMatrixWorld(true);
  const offset = PLANT_OFFSETS.reactor;
  function front(x, y) {
    const ray = new THREE.Raycaster(new THREE.Vector3(x + offset.x, y, 6 + offset.z), new THREE.Vector3(0, 0, -1));
    ray.layers.set(1);
    const hit = ray.intersectObjects(plant.scene.children, true)[0];
    assert.ok(hit);
    return hit.point.z - offset.z;
  }
  for (const x of [-3.7, 3.7]) {
    assert.ok(Math.abs(front(x, 2.2) - 1.87) < 0.01);
    assert.ok(Math.abs(front(x, 3.3) - 1.87) < 0.01);
    assert.ok(Math.abs(front(x, 3.8) - 1.98) < 0.01);
    assert.ok(front(x, 1.32) > 1.7);
    assert.ok(front(x, 0.5) > 1.9);
  }
  for (const x of [-4.5, 4.5]) {
    assert.ok(Math.abs(front(x, 3.2) + 4.15) < 0.01);
    assert.ok(Math.abs(front(x, 5.8) + 3.75) < 0.01);
    assert.ok(front(x, 6.6) > -5);
  }
});

test('reduced motion fixes coupling stripes to snapshot speed and keeps the vent still', t => {
  const { plant } = fixture(t, true);
  const snap = snapshot();
  snap.truth.secondary.steam_dump_percent = 50;
  snap.truth.primary.loops[1].pump_speed_percent = 60;
  plant.update(snap);
  const coupling = named(plant, 'Pump B coupling');
  const vent = named(plant, 'Roof vent plume');
  const positions = vent.children.map(sprite => sprite.position.toArray());
  assert.equal(coupling.rotation.y, -0.6 * Math.PI);
  for (let i = 0; i < 10; i++) assert.equal(plant.advance(0.25), false);
  assert.equal(coupling.rotation.y, -0.6 * Math.PI);
  assert.deepEqual(vent.children.map(sprite => sprite.position.toArray()), positions);
  snap.truth.primary.loops[1].pump_speed_percent = 15;
  plant.update(snap);
  assert.equal(coupling.rotation.y, -0.15 * Math.PI);
});

test('high bay lights pool downward with a cooler and dimmer containment deck', t => {
  const { plant } = fixture(t);
  const reactor = [];
  const hall = [];
  named(plant, 'Containment operating deck').traverse(object => {
    if (object.isSpotLight) reactor.push(object);
  });
  named(plant, 'Turbine hall').traverse(object => {
    if (object.isSpotLight) hall.push(object);
  });
  assert.equal(reactor.length, 4);
  assert.equal(hall.length, 4);
  for (const light of [...reactor, ...hall]) {
    assert.ok(light.position.y > 6);
    assert.equal(light.target.position.y, 0);
    assert.ok(light.penumbra > 0);
    assert.equal(light.castShadow, false);
  }
  assert.ok(reactor.every(light => light.intensity < hall[0].intensity));
  assert.ok(reactor.every(light => light.color.equals(new THREE.Color(theme.coldCoolant))));
  assert.ok(hall.every(light => light.color.equals(new THREE.Color(theme.plantKey))));
});

test('local steam flow dials read both true loops while reported readings are stuck', t => {
  const { plant, text } = fixture(t);
  const snap = snapshot();
  snap.truth.secondary.loops[0].steam_kg_s = 123.4;
  snap.truth.secondary.loops[1].steam_kg_s = 234.5;
  snap.readings = ['a', 'b'].map(loop => ({ sensor: { steam_flow: loop }, reading: { value: 999 }, fault: 'quiet' }));
  plant.update(snap);
  assert.ok(text.includes('123.4 kg/s'));
  assert.ok(text.includes('234.5 kg/s'));
  assert.equal(text.includes('999.0 kg/s'), false);
  const hall = named(plant, 'Turbine hall');
  const needles = hall.getObjectByName('Field gauge needles');
  const matrix = new THREE.Matrix4();
  for (const [i, flow] of [123.4, 234.5].entries()) {
    needles.getMatrixAt(i + 1, matrix);
    const angle = Math.atan2(matrix.elements[1], matrix.elements[0]);
    assert.ok(Math.abs(angle - (Math.PI * 0.75 - Math.PI * 1.5 * flow / 1000)) < 1e-6);
  }
});
