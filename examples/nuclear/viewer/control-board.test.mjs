import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import * as THREE from '../../../observe/downloads/vendor/three/build/three.module.js';
import { KNOBS, PALETTE_TOKENS } from './control-room.mjs';
import { POINTS } from './instruments.mjs';
import { BOARDS, BOARD, ROOM, STANDING_SPOTS, DEFAULT_VIEW, ANNUNCIATOR_WINDOWS, fitSpot, devicePlacements, boardPoint } from './board-layout.mjs';

// Only the graphics context and environment capture are replaced. Scene construction stays real.
const lookURL = new URL('./look.mjs', import.meta.url).href;
const threeURL = new URL('../../../observe/downloads/vendor/three/build/three.module.js', import.meta.url).href;
const graphicsURL = `data:text/javascript,${encodeURIComponent(`
  export * from '${lookURL}';
  import * as THREE from '${threeURL}';
  export const renderers = [];
  export function createEnvironment() { return { texture: null, dispose() {} }; }
  export function createRenderer() {
    const renderer = {
      domElement: document.createElement('canvas'),
      capabilities: { getMaxAnisotropy: () => 4 },
      frames: [],
      info: { render: { calls: 0, triangles: 0 }, reset() { this.render = { calls: 0, triangles: 0 }; } },
      setPixelRatio() {}, setSize() {}, setRenderTarget() {}, dispose() {}, forceContextLoss() {},
      render(scene, camera) {
        scene.updateMatrixWorld(true);
        camera.updateMatrixWorld(true);
        const matrix = new THREE.Matrix4().multiplyMatrices(camera.projectionMatrix, camera.matrixWorldInverse);
        const frustum = new THREE.Frustum().setFromProjectionMatrix(matrix);
        let calls = 0;
        let triangles = 0;
        scene.traverseVisible(mesh => {
          if ((!mesh.isMesh && !mesh.isSprite) || !mesh.material.visible || !mesh.layers.test(camera.layers)) return;
          if (mesh.frustumCulled) {
            const intersects = mesh.isSprite ? frustum.intersectsSprite(mesh) : frustum.intersectsObject(mesh);
            if (!intersects) return;
          }
          const count = mesh.isInstancedMesh ? mesh.count : 1;
          if (!count) return;
          const passes = mesh.material.transparent && mesh.material.side === THREE.DoubleSide && !mesh.material.forceSinglePass ? 2 : 1;
          calls += passes;
          if (mesh.isSprite) triangles += 2;
          else triangles += (mesh.geometry.index?.count ?? mesh.geometry.attributes.position.count) / 3 * count * passes;
        });
        this.info.render.calls += calls;
        this.info.render.triangles += triangles;
        this.frames.push({ scene, camera, calls, triangles });
      },
    };
    renderers.push(renderer);
    return renderer;
  }
`)}`;
const hook = registerHooks({
  resolve(specifier, context, next) {
    if (specifier === '/vendor/three/build/three.module.js') return { url: threeURL, shortCircuit: true };
    if (specifier === './look.mjs' && context.parentURL === new URL('./control-board.mjs', import.meta.url).href) {
      return { url: graphicsURL, shortCircuit: true };
    }
    return next(specifier, context);
  },
});
const { createControlBoard } = await import('./control-board.mjs');
const { renderers } = await import(graphicsURL);
hook.deregister();

const css = readFileSync(new URL('./viewer.css', import.meta.url), 'utf8');
const tokens = Object.fromEntries([...css.match(/:root\s*\{([^}]+)\}/)[1].matchAll(/(--[\w-]+):\s*(#[\da-f]+);/g)]
  .map(([, name, color]) => [name, color]));
const theme = Object.fromEntries(Object.entries(PALETTE_TOKENS).map(([name, token]) => [name, tokens[token]]));

function fixture(t, reducedMotion = () => true) {
  const frames = new Map();
  let frameNumber = 0;
  let resize;
  const targets = [];
  const eventTarget = () => {
    const target = new EventTarget();
    const listeners = new Map();
    const add = target.addEventListener.bind(target);
    const remove = target.removeEventListener.bind(target);
    target.addEventListener = (type, fn) => {
      listeners.set(fn, type);
      add(type, fn);
    };
    target.removeEventListener = (type, fn) => {
      listeners.delete(fn);
      remove(type, fn);
    };
    target.listeners = listeners;
    targets.push(target);
    return target;
  };
  const makeElement = () => {
    const ctx = { measureText: value => ({ width: value.length * 5 }),
      createRadialGradient: () => ({ addColorStop() {} }) };
    for (const name of ['drawImage', 'fillRect', 'clearRect', 'strokeRect', 'fillText', 'save', 'restore', 'translate', 'scale',
      'beginPath', 'moveTo', 'lineTo', 'stroke']) ctx[name] = () => {};
    return Object.assign(eventTarget(), {
      style: {}, dataset: {}, clientWidth: 785, clientHeight: 491,
      getContext: () => ctx, setAttribute() {}, append() {}, remove() {},
      focus() { document.activeElement = this; },
    });
  };
  const globals = {
    document: Object.assign(eventTarget(), { createElement: makeElement }),
    window: Object.assign(eventTarget(), { devicePixelRatio: 1 }),
    ResizeObserver: class { constructor(callback) { resize = callback; } observe() {} disconnect() {} },
    IntersectionObserver: class { observe() {} disconnect() {} },
    requestAnimationFrame: callback => { frames.set(++frameNumber, callback); return frameNumber; },
    cancelAnimationFrame: id => frames.delete(id),
  };
  const restore = [];
  for (const [name, value] of Object.entries(globals)) {
    const previous = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
    restore.push(() => {
      if (previous) Object.defineProperty(globalThis, name, previous);
      else delete globalThis[name];
    });
  }
  const knobs = KNOBS.filter(knob => knob.group === 'plant');
  const container = makeElement();
  const stage = createControlBoard(container, {
    knobIds: knobs.map(knob => knob.id), knobLabels: knobs.map(knob => knob.label), knobKinds: knobs.map(knob => knob.kind),
    theme, reducedMotion, onDevice() {},
  });
  stage.updatePlant({
    at_ms: 1000, revision: 1, operator_actions: 0,
    telemetry: { quiet: false, heartbeat: 1, last_sample_ms: 1000 },
    reported_status: {}, readings: [], alarms: [], faults: { process: [] },
    truth: {
      reactor: { neutron_power_percent: 100, control_rod_percent: 80,
        shutdown_rod_percent_inserted: 0, core_exit_c: 325, trip: null },
      primary: {
        pressure_mpa: 15.5, level_percent: 55, heaters_on: false, spray_percent: 0, relief_open: false,
        loops: [0, 1].map(() => ({ hot_leg_c: 325, cold_leg_c: 290, flow_percent: 100,
          pump_running: true, pump_speed_percent: 100 })),
      },
      secondary: {
        loops: [0, 1].map(() => ({ steam_kg_s: 400, feed_kg_s: 400, level_percent: 50, feed_valve_percent: 60 })),
        feed_pumps_running: [true, true], steam_pressure_mpa: 6.9, turbine_valve_percent: 90,
        turbine_tripped: false, generator_mw: 600, condenser_pressure_kpa: 5,
        circulating_water_running: true, steam_dump_percent: 0, steam_relief_open: false,
      },
    },
  });
  const pairs = POINTS.map(point => ({ ...point, reported: point.range[0], trueValue: point.range[0], gap: 0 }));
  const view = { pairs, alarms: [], telemetry: { quiet: false },
    reportedStatus: { coolantPumpsRunning: [true, true], feedPumpsRunning: [true, true] } };
  const text = { plantTime: '0:01.0', telemetry: 'Telemetry live, heartbeat 1' };
  stage.update(view, text, []);
  let time = performance.now();
  function draw(elapsed = 16) {
    time += elapsed;
    const pending = [...frames.values()];
    frames.clear();
    pending.forEach(callback => callback(time));
  }
  draw();
  const renderer = renderers.at(-1);
  t.after(() => {
    stage.dispose();
    restore.forEach(reset => reset());
  });
  return { stage, renderer, container, draw, view, text, targets, resize: () => resize() };
}

test('the built room uses lit surfaces, baked geometry and bounded geometry cost', t => {
  const f = fixture(t);
  const frame = f.renderer.frames.at(-1);
  const room = frame.scene;
  const lights = [];
  const baked = [];
  room.traverse(object => {
    if (object.isLight) lights.push(object);
    if (!object.isMesh) return;
    assert.equal(object.material.isMeshBasicMaterial, undefined);
    assert.equal(object.material.toneMapped, true);
    if (object.geometry.attributes.color) baked.push(object);
    if (object.material.emissiveMap) assert.ok(object.material.emissiveIntensity > 0);
  });
  assert.ok(lights.filter(light => light.castShadow).length <= 1);
  assert.ok(lights.every(light => !light.isRectAreaLight));
  assert.ok(baked.length >= 5);
  assert.ok(baked.some(mesh => {
    const values = mesh.geometry.attributes.color.array;
    return Math.max(...values) - Math.min(...values) > 0.2;
  }));
  assert.ok(f.renderer.info.render.calls <= 98, `${f.renderer.info.render.calls} calls including CCTV`);
  assert.ok(f.renderer.info.render.triangles <= 80296, `${f.renderer.info.render.triangles} triangles including CCTV`);
  t.diagnostic(`Estimated visible room: ${frame.calls} calls, ${frame.triangles} triangles.`);
  t.diagnostic(`Including CCTV: ${f.renderer.info.render.calls} calls, ${f.renderer.info.render.triangles} triangles.`);
  for (const pair of f.view.pairs) {
    pair.marked = true;
    pair.frozen = true;
  }
  f.view.alarms = ANNUNCIATOR_WINDOWS.map(({ key }, index) => ({
    key, state: index % 2 ? 'active' : 'normal',
  }));
  f.stage.update(f.view, f.text, []);
  f.draw(250);
  assert.ok(f.renderer.info.render.calls <= 101);
  assert.ok(f.renderer.info.render.triangles <= 82564);
  const windows = [];
  room.traverse(mesh => {
    if (mesh.isInstancedMesh && mesh.material.userData.paletteToken === 'lampOff') windows.push(mesh);
  });
  assert.equal(windows.length, 2);
  assert.equal(windows.reduce((sum, mesh) => sum + mesh.count, 0), ANNUNCIATOR_WINDOWS.length);
  assert.ok(windows.every(mesh => mesh.count > 0));
  t.diagnostic(`Held and marked, with mixed alarms and CCTV: ${f.renderer.info.render.calls} calls, `
    + `${f.renderer.info.render.triangles} triangles.`);
});

test('rendered nameplates and hit volumes fit every section at both measured canvas sizes', t => {
  const f = fixture(t);
  for (const [width, height] of [[785, 491], [692, 433]]) {
    f.container.clientWidth = width;
    f.container.clientHeight = height;
    f.resize();
    for (const board of BOARDS) {
      f.stage.setView(board.view);
      f.draw();
      const { scene, camera } = f.renderer.frames.at(-1);
      const spot = STANDING_SPOTS[board.view];
      const fitted = fitSpot(board, width / height, spot.fov);
      assert.equal(camera.fov, spot.fov);
      assert.equal(camera.position.x, fitted.x);
      assert.equal(camera.position.z, fitted.z);
      assert.equal(camera.position.y, ROOM.eye);
      assert.equal(camera.aspect, width / height);
      scene.updateMatrixWorld(true);
      const plantKnobs = KNOBS.filter(knob => knob.group === 'plant');
      const placements = devicePlacements(KNOBS);
      let labels = 0;
      scene.traverse(mesh => {
        const index = mesh.userData.device;
        if (!mesh.isMesh || index === undefined || plantKnobs[index].board !== board.id) return;
        if (mesh.userData.hitVolume) {
          const size = new THREE.Vector3();
          mesh.getWorldScale(size);
          assert.ok(size.x >= 0.16 && size.z >= 0.16);
          assert.equal(mesh.material.visible, false);
          const world = new THREE.Vector3();
          mesh.getWorldPosition(world);
          const placement = placements.find(p => p.id === plantKnobs[index].id);
          assert.ok(Math.hypot(world.x - placement.position.x, world.z - placement.position.z) < 0.03);
          const up = new THREE.Vector3(0, 1, 0).transformDirection(mesh.matrixWorld);
          const origin = world.clone().addScaledVector(up, 0.3);
          const ray = new THREE.Raycaster(origin, up.negate());
          assert.ok(ray.intersectObject(mesh).length > 0, 'invisible grab volume remains raycastable');
        }
        if (!mesh.material.map || mesh.geometry.parameters.width !== 0.6) return;
        labels++;
        assert.ok(mesh.position.z < -0.3, 'the nameplate sits toward the panel above its device');
        const labelCenter = new THREE.Vector3();
        mesh.getWorldPosition(labelCenter);
        const deviceCenter = mesh.parent.position.clone();
        assert.ok(labelCenter.project(camera).y > deviceCenter.project(camera).y);
        assert.equal(mesh.geometry.parameters.height * mesh.parent.scale.y, 0.04);
        assert.equal(mesh.geometry.parameters.width * mesh.parent.scale.x, 0.15);
        const positions = mesh.geometry.attributes.position;
        for (let i = 0; i < positions.count; i++) {
          const point = new THREE.Vector3().fromBufferAttribute(positions, i).applyMatrix4(mesh.matrixWorld).project(camera);
          assert.ok(Math.abs(point.x) <= 0.92 && Math.abs(point.y) <= 0.92 && point.z < 1, plantKnobs[index].id);
        }
      });
      assert.equal(labels, plantKnobs.filter(knob => knob.board === board.id).length);
      const p = boardPoint(board, -BOARD.width / 2, BOARD.deskY, BOARD.deskDepth);
      const front = new THREE.Vector3(p.x, p.y, p.z).project(camera);
      assert.ok(Math.abs(front.x) <= 0.92 && Math.abs(front.y) <= 0.92 && front.z < 1);
    }
  }
});

function frameCoverage(scene, camera) {
  const columns = 80;
  const rows = 50;
  const surfaces = [];
  scene.traverseVisible(mesh => {
    if (mesh.isMesh && mesh.material.visible) surfaces.push(mesh);
  });
  let floor = 0;
  let ceiling = 0;
  const ray = new THREE.Raycaster();
  for (let y = 0; y < rows; y++) for (let x = 0; x < columns; x++) {
    ray.setFromCamera(new THREE.Vector2(2 * (x + 0.5) / columns - 1, 1 - 2 * (y + 0.5) / rows), camera);
    const hit = ray.intersectObjects(surfaces, false)[0];
    assert.ok(hit, `the room encloses ray ${x}, ${y}: ${ray.ray.direction.toArray()}`);
    if (hit.point.y <= 0.001) floor++;
    if (hit.point.y >= ROOM.height - 0.06) ceiling++;
  }
  return { floor: floor / (columns * rows), ceiling: ceiling / (columns * rows) };
}

test('the establishing frame limits visible floor and ceiling at both measured canvases', t => {
  const f = fixture(t);
  const measurements = [];
  for (const [width, height] of [[785, 491], [692, 433]]) {
    f.container.clientWidth = width;
    f.container.clientHeight = height;
    f.resize();
    f.draw();
    const { scene, camera } = f.renderer.frames.at(-1);
    const coverage = frameCoverage(scene, camera);
    measurements.push(coverage);
    t.diagnostic(`${width} by ${height}: floor ${(100 * coverage.floor).toFixed(2)}%; ceiling ${(100 * coverage.ceiling).toFixed(2)}%.`);
  }
  for (const coverage of measurements) {
    assert.ok(coverage.floor <= 0.42, `floor coverage ${coverage.floor} exceeds forty-two percent`);
    assert.ok(coverage.ceiling <= 0.2, `ceiling coverage ${coverage.ceiling} exceeds twenty percent`);
  }
});

test('reduced motion switches each view field of view and projection immediately', t => {
  const f = fixture(t);
  for (const name of [DEFAULT_VIEW, 'loops-board', 'cctv', 'door', DEFAULT_VIEW]) {
    f.stage.setView(name);
    f.draw();
    const { camera } = f.renderer.frames.at(-1);
    assert.equal(camera.fov, STANDING_SPOTS[name].fov);
    const scale = 1 / Math.tan(camera.fov * Math.PI / 360);
    assert.ok(Math.abs(camera.projectionMatrix.elements[5] - scale) < 1e-10);
  }
});

test('the rendered glide changes optics and finishes at the target field of view', t => {
  let reduced = false;
  const f = fixture(t, () => reduced);
  const start = STANDING_SPOTS[DEFAULT_VIEW];
  const end = STANDING_SPOTS['loops-board'];
  f.stage.setView('loops-board');
  f.draw(400);
  const { camera } = f.renderer.frames.at(-1);
  assert.ok(camera.fov > start.fov && camera.fov < end.fov);
  assert.ok(Math.abs(camera.projectionMatrix.elements[5] - 1 / Math.tan(camera.fov * Math.PI / 360)) < 1e-10);
  f.draw(400);
  assert.equal(camera.fov, end.fov);
  f.stage.setView(DEFAULT_VIEW);
  reduced = true;
  f.draw();
  assert.equal(camera.fov, start.fov);
  assert.equal(camera.position.z, start.z);
});

test('resizing during a section glide fits the section at its own field of view', t => {
  const f = fixture(t, () => false);
  f.stage.setView('loops-board');
  f.draw(200);
  f.container.clientWidth = 692;
  f.container.clientHeight = 433;
  f.resize();
  f.draw();
  const { camera } = f.renderer.frames.at(-1);
  const spot = STANDING_SPOTS['loops-board'];
  const fitted = fitSpot(BOARDS[2], 692 / 433, spot.fov);
  assert.equal(camera.fov, spot.fov);
  assert.equal(camera.position.x, fitted.x);
  assert.equal(camera.position.z, fitted.z);
});

test('one canvas walks through every space, looks in the plant, teleports back, and releases every listener', t => {
  const f = fixture(t);
  const canvas = f.renderer.domElement;
  f.stage.setView('door');
  f.draw();
  const sharedCamera = f.renderer.frames.at(-1).camera;
  canvas.focus();
  canvas.dispatchEvent(Object.assign(new Event('keydown', { cancelable: true }), { code: 'KeyW' }));
  const visited = new Set();
  let previousZ = sharedCamera.position.z;
  for (let i = 0; i < 200 && sharedCamera.position.z < 35; i++) {
    f.draw(100);
    const frame = f.renderer.frames.at(-1);
    assert.equal(frame.camera, sharedCamera);
    assert.ok(Math.abs(frame.camera.position.z - previousZ - 0.17) < 1e-8);
    assert.equal(frame.camera.position.y, ROOM.eye);
    assert.equal(canvas.style.opacity, '1');
    previousZ = frame.camera.position.z;
    visited.add(f.container.dataset.view);
  }
  assert.deepEqual([...visited], ['Door to the plant', 'Plant corridor', 'Turbine hall', 'Personnel airlock', 'Containment operating deck']);
  canvas.dispatchEvent(Object.assign(new Event('keyup', { cancelable: true }), { code: 'KeyW' }));
  canvas.dispatchEvent(Object.assign(new Event('pointerdown'), { button: 0, clientX: 100, clientY: 100 }));
  const yaw = sharedCamera.rotation.y;
  document.dispatchEvent(Object.assign(new Event('pointermove'), { clientX: 140, clientY: 120 }));
  f.draw();
  assert.ok(Math.abs(sharedCamera.rotation.y - yaw) > 0.09);
  canvas.dispatchEvent(new Event('pointerup'));
  for (const view of ['turbine', 'reactor', 'cctv', 'door', DEFAULT_VIEW]) {
    f.stage.setView(view);
    f.draw();
    assert.equal(f.renderer.frames.at(-1).camera, sharedCamera);
  }
  assert.ok(f.targets.some(target => target.listeners.size > 0));
  f.stage.dispose();
  assert.ok(f.targets.every(target => target.listeners.size === 0));
});

test('crossing fades in the new space while walking continues on the same camera', t => {
  let reduced = true;
  const f = fixture(t, () => reduced);
  const canvas = f.renderer.domElement;
  f.stage.setView('door');
  f.draw();
  reduced = false;
  canvas.focus();
  canvas.dispatchEvent(Object.assign(new Event('keydown', { cancelable: true }), { code: 'KeyW' }));
  for (let i = 0; i < 30 && f.container.dataset.view !== 'Plant corridor'; i++) f.draw(100);
  assert.equal(f.container.dataset.view, 'Plant corridor');
  assert.equal(canvas.style.opacity, '0');
  const camera = f.renderer.frames.at(-1).camera;
  const z = camera.position.z;
  f.draw(90);
  assert.equal(canvas.style.opacity, '0.5');
  assert.ok(camera.position.z > z);
  f.draw(90);
  assert.equal(canvas.style.opacity, '1');
});
