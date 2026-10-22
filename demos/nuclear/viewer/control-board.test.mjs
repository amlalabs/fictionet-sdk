import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import * as THREE from '../../../observe/downloads/vendor/three/build/three.module.js';
import { KNOBS, PALETTE_TOKENS } from './control-room.mjs';
import { POINTS } from './instruments.mjs';
import { SITE_EPOCH_SECONDS, siteTime } from './desk-screens.mjs';
import {
  BOARDS,
  BOARD,
  ROOM,
  STANDING_SPOTS,
  DEFAULT_VIEW,
  CCTV,
  ANNUNCIATOR_WINDOWS,
  fitSpot,
  devicePlacements,
  boardPoint,
} from './board-layout.mjs';

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
      shadowMap: { enabled: true, type: THREE.PCFSoftShadowMap, autoUpdate: false, needsUpdate: true },
      info: { render: { calls: 0, triangles: 0 }, reset() { this.render = { calls: 0, triangles: 0 }; } },
      setPixelRatio() {}, setSize() {}, setRenderTarget() {}, dispose() {}, forceContextLoss() {},
      render(scene, camera) {
        scene.updateMatrixWorld(true);
        camera.updateMatrixWorld(true);
        const matrix = new THREE.Matrix4().multiplyMatrices(camera.projectionMatrix, camera.matrixWorldInverse);
        const frustum = new THREE.Frustum().setFromProjectionMatrix(matrix);
        let calls = 0;
        let triangles = 0;
        let shadowCalls = 0;
        const draw = (mesh, frustum, shadow = false) => {
          if ((!mesh.isMesh && !mesh.isSprite) || !mesh.material.visible || !mesh.layers.test(camera.layers)) return;
          if (shadow && (!mesh.isMesh || !mesh.castShadow)) return;
          if (mesh.frustumCulled) {
            const intersects = mesh.isSprite ? frustum.intersectsSprite(mesh) : frustum.intersectsObject(mesh);
            if (!intersects) return;
          }
          const count = mesh.isInstancedMesh ? mesh.count : 1;
          if (!count) return;
          const doublePass = mesh.material.transparent && mesh.material.side === THREE.DoubleSide && !mesh.material.forceSinglePass;
          const passes = !shadow && doublePass ? 2 : 1;
          calls += passes;
          if (shadow) shadowCalls += passes;
          if (mesh.isSprite) triangles += 2;
          else triangles += (mesh.geometry.index?.count ?? mesh.geometry.attributes.position.count) / 3 * count * passes;
        };
        if (this.shadowMap.enabled && (this.shadowMap.autoUpdate || this.shadowMap.needsUpdate)) {
          let lights = 0;
          scene.traverseVisible(light => {
            if (!light.isLight || !light.castShadow || !light.layers.test(camera.layers)) return;
            lights++;
            if (!light.shadow.autoUpdate && !light.shadow.needsUpdate) return;
            for (let viewport = 0; viewport < light.shadow.getViewportCount(); viewport++) {
              light.shadow.updateMatrices(light, viewport);
              scene.traverseVisible(mesh => draw(mesh, light.shadow.getFrustum(), true));
            }
            light.shadow.needsUpdate = false;
          });
          if (lights) this.shadowMap.needsUpdate = false;
        }
        scene.traverseVisible(mesh => draw(mesh, frustum));
        this.info.render.calls += calls;
        this.info.render.triangles += triangles;
        this.frames.push({ scene, camera, calls, triangles, shadowCalls });
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
const tokens = Object.fromEntries(
  [...css.match(/:root\s*\{([^}]+)\}/)[1].matchAll(/(--[\w-]+):\s*(#[\da-f]+);/g)].map(([, name, color]) => [
    name,
    color,
  ]),
);
const theme = Object.fromEntries(Object.entries(PALETTE_TOKENS).map(([name, token]) => [name, tokens[token]]));

function fixture(t, reducedMotion = () => true) {
  const frames = new Map();
  const timers = new Map();
  let frameNumber = 0;
  let timerNumber = 0;
  let time = 0;
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
    const ctx = {
      calls: [],
      measureText: (value) => ({ width: value.length * 5 }),
      createRadialGradient: () => ({ addColorStop() {} }),
    };
    for (const name of [
      'drawImage',
      'fillRect',
      'clearRect',
      'strokeRect',
      'fillText',
      'save',
      'restore',
      'translate',
      'scale',
      'beginPath',
      'moveTo',
      'lineTo',
      'stroke',
      'closePath',
      'fill',
      'arc',
      'roundRect',
      'quadraticCurveTo',
    ]) {
      ctx[name] = (...args) => ctx.calls.push({ name, args });
    }
    return Object.assign(eventTarget(), {
      style: {},
      dataset: {},
      clientWidth: 785,
      clientHeight: 491,
      getContext: () => ctx,
      setAttribute() {},
      append() {},
      remove() {},
      focus() {
        document.activeElement = this;
      },
    });
  };
  const globals = {
    document: Object.assign(eventTarget(), { createElement: makeElement }),
    window: Object.assign(eventTarget(), { devicePixelRatio: 1 }),
    ResizeObserver: class {
      constructor(callback) {
        resize = callback;
      }
      observe() {}
      disconnect() {}
    },
    IntersectionObserver: class {
      observe() {}
      disconnect() {}
    },
    requestAnimationFrame: (callback) => {
      frames.set(++frameNumber, callback);
      return frameNumber;
    },
    cancelAnimationFrame: (id) => frames.delete(id),
    setTimeout: (callback, delay) => {
      timers.set(++timerNumber, { callback, at: time + delay });
      return timerNumber;
    },
    clearTimeout: (id) => timers.delete(id),
    performance: { now: () => time },
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
  const knobs = KNOBS.filter((knob) => knob.group === 'plant');
  const container = makeElement();
  const stage = createControlBoard(container, {
    knobIds: knobs.map((knob) => knob.id),
    knobLabels: knobs.map((knob) => knob.label),
    knobKinds: knobs.map((knob) => knob.kind),
    theme,
    reducedMotion,
    onDevice() {},
  });
  const snapshot = {
    at_ms: 1000,
    revision: 1,
    operator_actions: 0,
    telemetry: { quiet: false, heartbeat: 1, last_sample_ms: 1000 },
    reported_status: {},
    readings: [],
    alarms: [],
    faults: { process: [] },
    truth: {
      reactor: {
        neutron_power_percent: 100,
        control_rod_percent: 80,
        shutdown_rod_percent_inserted: 0,
        core_exit_c: 325,
        trip: null,
      },
      primary: {
        pressure_mpa: 15.5,
        level_percent: 55,
        heaters_on: false,
        spray_percent: 0,
        relief_open: false,
        loops: [0, 1].map(() => ({
          hot_leg_c: 325,
          cold_leg_c: 290,
          flow_percent: 100,
          pump_running: true,
          pump_speed_percent: 100,
        })),
      },
      secondary: {
        loops: [0, 1].map(() => ({ steam_kg_s: 400, feed_kg_s: 400, level_percent: 50, feed_valve_percent: 60 })),
        feed_pumps_running: [true, true],
        steam_pressure_mpa: 6.9,
        turbine_valve_percent: 90,
        turbine_tripped: false,
        generator_mw: 600,
        condenser_pressure_kpa: 5,
        circulating_water_running: true,
        steam_dump_percent: 0,
        steam_relief_open: false,
      },
    },
  };
  stage.updatePlant(snapshot);
  const pairs = POINTS.map((point) => ({ ...point, reported: point.range[0], trueValue: point.range[0], gap: 0 }));
  const view = {
    atMs: 1000,
    pairs,
    alarms: [],
    telemetry: { quiet: false },
    reportedStatus: { coolantPumpsRunning: [true, true], feedPumpsRunning: [true, true] },
  };
  const text = { plantTime: '0:01.0', telemetry: 'Telemetry live, heartbeat 1' };
  stage.update(view, text, []);
  function draw(elapsed = 16) {
    time += elapsed;
    for (const [id, timer] of timers) {
      if (timer.at > time) continue;
      timers.delete(id);
      timer.callback();
    }
    const pending = [...frames.values()];
    frames.clear();
    pending.forEach((callback) => callback(time));
  }
  draw();
  const renderer = renderers.at(-1);
  t.after(() => {
    stage.dispose();
    restore.forEach((reset) => reset());
  });
  return {
    stage,
    renderer,
    container,
    draw,
    view,
    text,
    targets,
    snapshot,
    frames,
    timers,
    now: () => time,
    resize: () => resize(),
  };
}

test('the built room uses lit surfaces, baked geometry and bounded geometry cost', (t) => {
  const f = fixture(t);
  const frame = f.renderer.frames.at(-1);
  const room = frame.scene;
  const lights = [];
  const baked = [];
  room.traverse((object) => {
    if (object.isLight) lights.push(object);
    if (!object.isMesh) return;
    assert.equal(object.material.isMeshBasicMaterial, undefined);
    assert.equal(object.material.toneMapped, !object.material.emissiveMap);
    if (object.geometry.attributes.color) baked.push(object);
    if (object.material.emissiveMap) assert.ok(object.material.emissiveIntensity > 0);
  });
  assert.ok(lights.filter((light) => light.castShadow).length <= 1);
  assert.ok(lights.every((light) => !light.isRectAreaLight));
  assert.ok(baked.length >= 5);
  assert.ok(
    baked.some((mesh) => {
      const values = mesh.geometry.attributes.color.array;
      return Math.max(...values) - Math.min(...values) > 0.2;
    }),
  );
  t.diagnostic(`Estimated visible room: ${frame.calls} calls, ${frame.triangles} triangles.`);
  t.diagnostic(`Including CCTV: ${f.renderer.info.render.calls} calls, ${f.renderer.info.render.triangles} triangles.`);
  assert.ok(f.renderer.info.render.calls < 60, `${f.renderer.info.render.calls} calls including CCTV`);
  assert.ok(f.renderer.info.render.triangles < 40000, `${f.renderer.info.render.triangles} triangles including CCTV`);
  for (const pair of f.view.pairs) {
    pair.marked = true;
    pair.frozen = true;
  }
  f.view.alarms = ANNUNCIATOR_WINDOWS.map(({ key }, index) => ({
    key,
    state: index % 2 ? 'active' : 'normal',
  }));
  f.stage.update(f.view, f.text, []);
  f.draw(250);
  assert.ok(f.renderer.info.render.calls < 60);
  assert.ok(f.renderer.info.render.triangles < 40000);
  const windows = [];
  room.traverse((mesh) => {
    if (mesh.isInstancedMesh && mesh.name === 'Annunciator windows') windows.push(mesh);
  });
  assert.equal(windows.length, 1);
  assert.equal(
    windows.reduce((sum, mesh) => sum + mesh.count, 0),
    ANNUNCIATOR_WINDOWS.length,
  );
  assert.ok(windows.every((mesh) => mesh.count > 0));
  const offsets = windows[0].geometry.attributes.atlasOffset;
  for (let i = 0; i < ANNUNCIATOR_WINDOWS.length; i++) {
    assert.equal(Math.round(offsets.getX(i) * 4) % 2, i % 2);
  }
  t.diagnostic(
    `Held and marked, with mixed alarms and CCTV: ${f.renderer.info.render.calls} calls, ` +
      `${f.renderer.info.render.triangles} triangles.`,
  );
});

test('rendered nameplates and hit volumes fit every section at both measured canvas sizes', (t) => {
  const f = fixture(t);
  for (const [width, height] of [
    [785, 491],
    [692, 433],
  ]) {
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
      const plantKnobs = KNOBS.filter((knob) => knob.group === 'plant');
      const placements = devicePlacements(KNOBS);
      let labels = 0;
      scene.traverse((mesh) => {
        const index = mesh.userData.device;
        if (!mesh.isMesh || index === undefined || plantKnobs[index].board !== board.id) return;
        if (mesh.userData.hitVolume) {
          const size = new THREE.Vector3();
          mesh.getWorldScale(size);
          assert.ok(size.x >= 0.16 && size.z >= 0.16);
          assert.equal(mesh.material.visible, false);
          const world = new THREE.Vector3();
          mesh.getWorldPosition(world);
          const placement = placements.find((p) => p.id === plantKnobs[index].id);
          assert.ok(Math.hypot(world.x - placement.position.x, world.z - placement.position.z) < 0.03);
          const up = new THREE.Vector3(0, 1, 0).transformDirection(mesh.matrixWorld);
          const origin = world.clone().addScaledVector(up, 0.3);
          const ray = new THREE.Raycaster(origin, up.negate());
          assert.ok(ray.intersectObject(mesh).length > 0, 'invisible grab volume remains raycastable');
        }
      });
      const nameplates = scene.getObjectByName('Device labels');
      nameplates.userData.devices.forEach((index, instance) => {
        if (plantKnobs[index].board !== board.id) return;
        let frame;
        scene.traverse((mesh) => {
          if (mesh.userData.hitVolume && mesh.userData.device === index) frame = mesh.parent;
        });
        const matrix = new THREE.Matrix4();
        nameplates.getMatrixAt(instance, matrix);
        const local = frame.matrixWorld.clone().invert().multiply(matrix);
        const mesh = nameplates;
        labels++;
        assert.ok(
          new THREE.Vector3().setFromMatrixPosition(local).z < -0.3,
          'the nameplate sits toward the panel above its device',
        );
        const labelCenter = new THREE.Vector3().setFromMatrixPosition(matrix);
        const deviceCenter = frame.position.clone();
        assert.ok(labelCenter.project(camera).y > deviceCenter.project(camera).y);
        assert.equal(mesh.geometry.parameters.height * frame.scale.y, 0.04);
        assert.equal(mesh.geometry.parameters.width * frame.scale.x, 0.15);
        const positions = mesh.geometry.attributes.position;
        for (let i = 0; i < positions.count; i++) {
          const point = new THREE.Vector3().fromBufferAttribute(positions, i).applyMatrix4(matrix).project(camera);
          assert.ok(Math.abs(point.x) <= 0.92 && Math.abs(point.y) <= 0.92 && point.z < 1, plantKnobs[index].id);
        }
      });
      assert.equal(labels, plantKnobs.filter((knob) => knob.board === board.id).length);
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
  scene.traverseVisible((mesh) => {
    if (mesh.isMesh && mesh.material.visible) surfaces.push(mesh);
  });
  let floor = 0;
  let ceiling = 0;
  const ray = new THREE.Raycaster();
  for (let y = 0; y < rows; y++)
    for (let x = 0; x < columns; x++) {
      ray.setFromCamera(new THREE.Vector2((2 * (x + 0.5)) / columns - 1, 1 - (2 * (y + 0.5)) / rows), camera);
      const hit = ray.intersectObjects(surfaces, false)[0];
      assert.ok(hit, `the room encloses ray ${x}, ${y}: ${ray.ray.direction.toArray()}`);
      if (hit.point.y <= 0.001) floor++;
      if (hit.point.y >= ROOM.height - 0.06) ceiling++;
    }
  return { floor: floor / (columns * rows), ceiling: ceiling / (columns * rows) };
}

test('the establishing frame limits visible floor and ceiling at both measured canvases', (t) => {
  const f = fixture(t);
  const measurements = [];
  for (const [width, height] of [
    [785, 491],
    [692, 433],
  ]) {
    f.container.clientWidth = width;
    f.container.clientHeight = height;
    f.resize();
    f.draw();
    const { scene, camera } = f.renderer.frames.at(-1);
    const coverage = frameCoverage(scene, camera);
    measurements.push(coverage);
    t.diagnostic(
      `${width} by ${height}: floor ${(100 * coverage.floor).toFixed(2)}%; ceiling ${(100 * coverage.ceiling).toFixed(2)}%.`,
    );
  }
  for (const coverage of measurements) {
    assert.ok(coverage.floor <= 0.42, `floor coverage ${coverage.floor} exceeds forty-two percent`);
    assert.ok(coverage.ceiling <= 0.2, `ceiling coverage ${coverage.ceiling} exceeds twenty percent`);
  }
});

test('reduced motion switches each view field of view and projection immediately', (t) => {
  const f = fixture(t);
  for (const name of [DEFAULT_VIEW, 'loops-board', 'cctv', 'door', DEFAULT_VIEW]) {
    f.stage.setView(name);
    f.draw();
    const { camera } = f.renderer.frames.at(-1);
    assert.equal(camera.fov, STANDING_SPOTS[name].fov);
    const scale = 1 / Math.tan((camera.fov * Math.PI) / 360);
    assert.ok(Math.abs(camera.projectionMatrix.elements[5] - scale) < 1e-10);
  }
});

test('the rendered glide changes optics and finishes at the target field of view', (t) => {
  let reduced = false;
  const f = fixture(t, () => reduced);
  const start = STANDING_SPOTS[DEFAULT_VIEW];
  const end = STANDING_SPOTS['loops-board'];
  f.stage.setView('loops-board');
  f.draw(400);
  const { camera } = f.renderer.frames.at(-1);
  assert.ok(camera.fov > start.fov && camera.fov < end.fov);
  assert.ok(Math.abs(camera.projectionMatrix.elements[5] - 1 / Math.tan((camera.fov * Math.PI) / 360)) < 1e-10);
  f.draw(400);
  assert.equal(camera.fov, end.fov);
  f.stage.setView(DEFAULT_VIEW);
  reduced = true;
  f.draw();
  assert.equal(camera.fov, start.fov);
  assert.equal(camera.position.z, start.z);
});

test('resizing during a section glide fits the section at its own field of view', (t) => {
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

test('one canvas walks through every space, looks in the plant, teleports back, and releases every listener', (t) => {
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
  assert.deepEqual(
    [...visited],
    ['Door to the plant', 'Plant corridor', 'Turbine hall', 'Personnel airlock', 'Containment operating deck'],
  );
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
  assert.ok(f.targets.some((target) => target.listeners.size > 0));
  f.stage.dispose();
  assert.ok(f.targets.every((target) => target.listeners.size === 0));
});

test('crossing fades in the new space while walking continues on the same camera', (t) => {
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

test('the site clock matches the HMI default and advances only by plant time', () => {
  const rust = readFileSync(new URL('../world/src/hmi.rs', import.meta.url), 'utf8');
  const defaults = rust.match(/impl Default for Site \{([\s\S]*?)impl Site/)[1];
  const epoch = Number(defaults.match(/epoch:\s*([\d_]+)/)[1].replaceAll('_', ''));
  assert.equal(SITE_EPOCH_SECONDS, epoch);
  assert.match(defaults, /zone: "GMT"/);
  assert.match(defaults, /utc_offset_seconds: 0/);
  assert.equal(siteTime(0), '2026-03-14 07:43:12 GMT');
  assert.equal(siteTime(1000), '2026-03-14 07:43:13 GMT');
  assert.equal(siteTime(86400000), '2026-03-15 07:43:12 GMT');
  assert.equal(siteTime(-1), '2026-03-14 07:43:11 GMT');
  assert.equal(siteTime(undefined), 'TIME UNAVAILABLE');
});

function displays(scene) {
  const result = [];
  scene.traverse((mesh) => {
    if (mesh.isMesh && mesh.material.emissiveMap?.isCanvasTexture) result.push(mesh);
  });
  return result;
}

function paintedText(mesh) {
  return mesh.material.map.image
    .getContext('2d')
    .calls.filter((call) => call.name === 'fillText')
    .map((call) => call.args[0]);
}

test('desk screens use all four layouts, reported values and throttled display signatures', (t) => {
  const f = fixture(t);
  const desks = displays(f.renderer.frames.at(-1).scene).filter((mesh) => mesh.material.map.image.width === 1024);
  assert.equal(desks.length, 4);
  const titles = ['HMI01 · PRIMARY OVERVIEW', 'HMI01 · ALARMS 1/2', 'HMI01 · SECONDARY OVERVIEW', 'HMI01 · ALARMS 2/2'];
  desks.forEach((mesh, i) => {
    assert.ok(paintedText(mesh).includes(titles[i]));
    assert.equal(mesh.material.isMeshStandardMaterial, true);
    const bounds = new THREE.Box3().setFromObject(mesh);
    const center = bounds.getCenter(new THREE.Vector3());
    assert.ok(Math.abs(center.x - [-2.16, -1.14, 1.14, 2.16][i]) < 0.001);
  });
  const versions = () => desks.map((mesh) => mesh.material.map.version);
  const initial = versions();
  const hot = f.view.pairs.find((pair) => pair.key === 'hot_leg:b');
  hot.reported = 323.6;
  hot.trueValue = 330;
  f.stage.update(f.view, f.text, []);
  f.draw(100);
  assert.deepEqual(versions(), initial);
  f.stage.update(f.view, f.text, []);
  f.draw(900);
  assert.deepEqual(
    versions(),
    initial.map((version, i) => version + Number(i === 0)),
  );
  assert.ok(paintedText(desks[0]).includes('323.6 C'));
  assert.ok(!paintedText(desks[0]).includes('330.0 C'));
  const updated = versions();
  hot.trueValue = 400;
  f.view.atMs += 1000;
  f.stage.update(f.view, f.text, []);
  f.draw(1000);
  assert.deepEqual(versions(), updated);
  f.view.alarms = [{ key: 'reactor_tripped', state: 'active' }];
  f.stage.update(f.view, f.text, []);
  f.draw(1000);
  assert.ok(paintedText(desks[3]).includes('Active'));
  assert.equal(versions()[3], updated[3] + 1);
});

test('the monitor bank frames the main feed and keeps its caption on plant time', (t) => {
  const f = fixture(t);
  const room = f.renderer.frames.at(-1).scene;
  const bank = displays(room).find((mesh) => mesh.material.map.image.width === 1030);
  assert.ok(bank);
  assert.equal(bank.material.isMeshStandardMaterial, true);
  assert.ok(paintedText(bank).includes('NO SIGNAL'));
  assert.ok(paintedText(bank).includes('CAM 03 CONTAINMENT · 2026-03-14 07:43:13 GMT'));
  const shader = { uniforms: {}, fragmentShader: THREE.ShaderLib.standard.fragmentShader };
  bank.material.onBeforeCompile(shader);
  assert.equal(shader.uniforms.containmentFeed.value.isRenderTargetTexture, true);
  assert.match(shader.fragmentShader, /diffuseColor \*= monitorBank\(map, vMapUv\)/);
  assert.match(shader.fragmentShader, /totalEmissiveRadiance \*= monitorBank/);
  const texture = bank.material.map;
  const version = texture.version;
  f.stage.update(f.view, f.text, []);
  f.draw(1000);
  assert.equal(texture.version, version);
  const feedFrames = () => f.renderer.frames.filter((frame) => frame.camera !== f.renderer.frames.at(-1).camera).length;
  const before = feedFrames();
  f.view.atMs = 61000;
  f.stage.update(f.view, f.text, []);
  f.draw(100);
  assert.equal(feedFrames(), before);
  assert.equal(texture.version, version);
  f.stage.update(f.view, f.text, []);
  f.draw(100);
  assert.equal(feedFrames(), before + 1);
  assert.ok(paintedText(bank).includes('CAM 03 CONTAINMENT · 2026-03-14 07:44:13 GMT'));
  for (const [width, height] of [
    [785, 491],
    [692, 433],
  ]) {
    f.container.clientWidth = width;
    f.container.clientHeight = height;
    f.resize();
    f.stage.setView('cctv');
    f.draw();
    const { camera } = f.renderer.frames.at(-1);
    const corners = [];
    for (const z of [-CCTV.width / 2, CCTV.width / 2]) {
      for (const y of [-CCTV.height / 2, CCTV.height / 2]) {
        corners.push(new THREE.Vector3(CCTV.x + 0.06, CCTV.y + y, CCTV.z + z).project(camera));
      }
    }
    assert.ok(corners.every((p) => Math.abs(p.x) < 0.92 && Math.abs(p.y) < 0.92 && p.z < 1));
    const share = (Math.max(...corners.map((p) => p.x)) - Math.min(...corners.map((p) => p.x))) / 2;
    assert.ok(share >= 0.68 && share <= 0.72, String(share));
    const bounds = new THREE.Box3().setFromObject(bank);
    assert.ok(Math.abs(bounds.max.z - bounds.min.z - CCTV.bankWidth) < 0.001);
    for (const y of [bounds.min.y, bounds.max.y]) {
      for (const z of [bounds.min.z, bounds.max.z]) {
        const p = new THREE.Vector3(bounds.max.x, y, z).project(camera);
        assert.ok(Math.abs(p.x) < 1 && Math.abs(p.y) < 1);
      }
    }
    t.diagnostic(
      `${width} by ${height}: main CCTV width ${(share * 100).toFixed(2)}%, ${(share * width).toFixed(1)} px.`,
    );
  }
});

test('every standing view fits the frame budget with and without a CCTV refresh', (t) => {
  const f = fixture(t);
  f.container.clientWidth = 1440;
  f.container.clientHeight = 900;
  f.resize();
  let maxCalls = 0;
  let maxTriangles = 0;
  for (const state of ['normal', 'held', 'mixed', 'held with steam', 'mixed with steam']) {
    const held = state.startsWith('held');
    const mixed = state.startsWith('mixed');
    f.view.pairs.forEach((pair, i) => {
      pair.marked = state !== 'normal' && (!mixed || i % 3 !== 0);
      pair.frozen = held || (mixed && i % 3 !== 1);
    });
    f.snapshot.truth.primary.spray_percent = state.includes('steam') ? 100 : 0;
    f.snapshot.truth.primary.relief_open = state.includes('steam');
    f.snapshot.truth.secondary.steam_relief_open = state.includes('steam');
    f.stage.updatePlant(f.snapshot);
    f.view.alarms = ANNUNCIATOR_WINDOWS.map(({ key }, i) => ({ key, state: i % 2 ? 'active' : 'normal' }));
    f.stage.update(f.view, f.text, []);
    for (const name of [...Object.keys(STANDING_SPOTS), 'reactor', 'turbine']) {
      f.stage.setView(name);
      f.draw(250);
      const refresh = { ...f.renderer.info.render };
      const main = f.renderer.frames.at(-1);
      assert.ok(refresh.calls < 60, `${state} ${name}: ${refresh.calls} calls`);
      assert.ok(refresh.triangles < 40000, `${state} ${name}: ${refresh.triangles} triangles`);
      maxCalls = Math.max(maxCalls, refresh.calls);
      maxTriangles = Math.max(maxTriangles, refresh.triangles);
      assert.equal(main.shadowCalls, 0);
      const before = f.renderer.frames.length;
      f.stage.update(f.view, f.text, []);
      f.draw(16);
      assert.equal(f.renderer.frames.length, before + 1);
      const cached = { ...f.renderer.info.render };
      assert.equal(cached.calls, main.calls);
      assert.equal(cached.triangles, main.triangles);
      if (state === 'normal') {
        t.diagnostic(
          `${name}: ${cached.calls} calls / ${cached.triangles} triangles; ` +
            `refresh ${refresh.calls} calls / ${refresh.triangles} triangles.`,
        );
      }
    }
  }
  t.diagnostic(`Maximum across all states and views: ${maxCalls} calls; ${maxTriangles} triangles.`);
});

test('window flashes change atlas offsets without repainting any canvas or requesting full rate frames', (t) => {
  let reduced = true;
  const f = fixture(t, () => reduced);
  f.snapshot.truth.primary.loops.forEach((loop) => {
    loop.pump_speed_percent = 0;
  });
  f.snapshot.truth.secondary.generator_mw = 0;
  f.snapshot.truth.secondary.turbine_valve_percent = 0;
  f.stage.updatePlant(f.snapshot);
  f.draw(250);
  reduced = false;
  f.view.alarms = [{ key: ANNUNCIATOR_WINDOWS[0].key, state: 'active' }];
  f.stage.update(f.view, f.text, []);
  f.draw(1000);
  const room = f.renderer.frames.at(-1).scene;
  const windows = room.getObjectByName('Annunciator windows');
  const textures = new Set();
  room.traverse((mesh) => {
    if (mesh.material?.map?.isCanvasTexture) textures.add(mesh.material.map);
  });
  const versions = [...textures].map((texture) => texture.version);
  assert.equal(f.frames.size, 0);
  const start = f.renderer.frames.length;
  const offsets = [];
  for (let i = 0; i < 1000; i++) {
    f.draw(1);
    if (i % 250 === 249) offsets.push(windows.geometry.attributes.atlasOffset.getX(0));
    assert.equal(f.frames.size, 0);
  }
  assert.equal(f.renderer.frames.length - start, 8);
  assert.equal(new Set(offsets).size, 2);
  assert.deepEqual(
    [...textures].map((texture) => texture.version),
    versions,
  );
  const shader = {
    uniforms: {},
    vertexShader: THREE.ShaderLib.standard.vertexShader,
    fragmentShader: THREE.ShaderLib.standard.fragmentShader,
  };
  windows.material.onBeforeCompile(shader);
  assert.match(shader.vertexShader, /attribute vec2 atlasOffset/);
  assert.match(shader.fragmentShader, /vAlarmMark > 0.5/);
  reduced = true;
  f.stage.update(f.view, f.text, []);
  f.draw(250);
  assert.equal(windows.geometry.attributes.alarmMark.getX(0), 1);
  assert.equal(f.frames.size, 0);
  assert.equal(f.timers.size, 0);
});

test('board text coalesces changes to one canvas upload per second', (t) => {
  const f = fixture(t);
  const room = f.renderer.frames.at(-1).scene;
  let board;
  room.traverse((mesh) => {
    if (mesh.material?.map?.image.width === 4200) board = mesh.material.map;
  });
  assert.ok(board);
  const start = board.version;
  for (let i = 0; i < 9; i++) {
    f.stage.update(f.view, { plantTime: String(i), telemetry: `Telemetry ${i}` }, []);
    f.draw(100);
    assert.equal(board.version, start);
  }
  f.draw(100);
  assert.equal(board.version, start + 1);
  assert.equal(f.timers.size, 0);
});

test('device motion reuses bounds and invalidates shadows only when casting geometry moves', (t) => {
  const f = fixture(t);
  const room = f.renderer.frames.at(-1).scene;
  const batches = [];
  room.traverse((mesh) => {
    if (mesh.isInstancedMesh && mesh.castShadow) batches.push(mesh);
  });
  assert.ok(batches.length > 0);
  batches.forEach((mesh) => {
    assert.equal(mesh.frustumCulled, false);
    mesh.computeBoundingSphere = () => assert.fail('device bounds must not be recomputed during rendering');
  });
  f.renderer.shadowMap.needsUpdate = false;
  f.stage.update(f.view, f.text, []);
  f.draw(16);
  assert.equal(f.renderer.shadowMap.needsUpdate, false);
  const knobs = KNOBS.filter((knob) => knob.group === 'plant');
  const states = knobs.map((knob) => ({
    fraction: 0,
    travel: 0,
    depth: 0,
    value: 0,
    cover: { open: false, fired: false },
  }));
  const dial = knobs.findIndex((knob) => knob.kind === 'dial');
  states[dial].fraction = 0.5;
  f.stage.update(f.view, f.text, states);
  f.draw(16);
  assert.equal(f.renderer.shadowMap.needsUpdate, true);
});

test('all installed display materials preserve ink after their shader hooks and theme changes', (t) => {
  const f = fixture(t);
  const room = f.renderer.frames.at(-1).scene;
  const surfaces = displays(room);
  assert.equal(surfaces.length, 6);
  for (const palette of [theme, { ...theme, ink: theme.lampInk }]) {
    f.stage.setTheme(palette);
    f.draw(1000);
    for (const { material } of surfaces) {
      assert.equal(material.toneMapped, false);
      assert.equal(material.emissiveIntensity, 1);
      assert.equal(material.color.getHex(), 0);
      assert.equal(material.envMapIntensity, 0);
      const output = new THREE.Color(palette.ink)
        .multiply(material.emissive)
        .multiplyScalar(material.emissiveIntensity);
      assert.equal(output.getHexString(), palette.ink.slice(1));
      const shader = {
        uniforms: {},
        vertexShader: THREE.ShaderLib.standard.vertexShader,
        fragmentShader: THREE.ShaderLib.standard.fragmentShader,
      };
      material.onBeforeCompile(shader);
      assert.match(shader.fragmentShader, /outgoingLight = totalEmissiveRadiance;\n#include <opaque_fragment>/);
    }
  }
});

test('camera motion keeps CCTV at its own cadence and counts only passes that ran', (t) => {
  const f = fixture(t, () => false);
  f.stage.setView('loops-board');
  const start = f.renderer.frames.length;
  const feed = f.renderer.frames[0].camera;
  const refreshes = [];
  for (let i = 0; i < 100; i++) {
    const before = f.renderer.frames.length;
    f.draw(10);
    const passes = f.renderer.frames.slice(before);
    if (passes.some((pass) => pass.camera === feed)) refreshes.push(f.now());
    if (!passes.length) continue;
    assert.equal(
      f.renderer.info.render.calls,
      passes.reduce((sum, pass) => sum + pass.calls, 0),
    );
    assert.equal(
      f.renderer.info.render.triangles,
      passes.reduce((sum, pass) => sum + pass.triangles, 0),
    );
  }
  assert.equal(refreshes.length, 5);
  assert.ok(refreshes.every((time, i) => !i || time - refreshes[i - 1] === 200));
  assert.ok(f.renderer.frames.length - start > 50);
});

test('the counting renderer includes instancing, transparent back faces and static shadow passes', () => {
  const renderer = renderers.at(-1);
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 20);
  camera.position.z = 5;
  const material = new THREE.MeshStandardMaterial({ transparent: true, side: THREE.DoubleSide });
  const geometry = new THREE.BoxGeometry();
  const mesh = new THREE.InstancedMesh(geometry, material, 3);
  mesh.castShadow = true;
  for (let i = 0; i < 3; i++) mesh.setMatrixAt(i, new THREE.Matrix4());
  scene.add(mesh);
  const light = new THREE.DirectionalLight();
  light.position.set(0, 3, 5);
  light.castShadow = true;
  scene.add(light, light.target);
  renderer.shadowMap.needsUpdate = true;
  renderer.info.reset();
  renderer.render(scene, camera);
  assert.deepEqual(renderer.info.render, { calls: 3, triangles: 108 });
  assert.equal(renderer.frames.at(-1).shadowCalls, 1);
  renderer.info.reset();
  renderer.render(scene, camera);
  assert.deepEqual(renderer.info.render, { calls: 2, triangles: 72 });
  material.forceSinglePass = true;
  renderer.info.reset();
  renderer.render(scene, camera);
  assert.deepEqual(renderer.info.render, { calls: 1, triangles: 36 });
  mesh.dispose();
  material.dispose();
  geometry.dispose();
  light.dispose();
});
