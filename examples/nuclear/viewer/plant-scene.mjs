// Plant interiors use snapshot truth. Motion only interpolates the picture.
import * as THREE from '/vendor/three/build/three.module.js';
import { formatGap, formatValue, instruments } from './instruments.mjs';
import { createMaterial, createLighting, applyMaterialPalette, setIndicator } from './look.mjs';
import { look, walk, walkDelta } from './room-motion.mjs';

const TAU = Math.PI * 2;
const HALF_PI = Math.PI / 2;
const HALL_X = 40;
const SPIN = 9;
const clamp01 = value => Math.max(0, Math.min(1, value));
export const VIEWS = {
  overview: { eye: [0, 1.7, 7.8], look: [0, 2.5, -2] },
  reactor: { eye: [0, 1.7, 7.8], look: [0, 2.5, -2] },
  turbine: { eye: [HALL_X - 9, 1.7, 6.4], look: [HALL_X + 0.5, 2.2, -0.5] },
};

function targetsFrom(r) {
  const steam = clamp01(r.loops.reduce((sum, loop) => sum + loop.steamKgS, 0) / 800);
  return {
    rods: clamp01(r.reactor.controlRodWithdrawnPercent / 100),
    shutdown: 1 - clamp01(r.reactor.shutdownRodInsertedPercent / 100),
    pumps: r.loops.map(loop => clamp01(loop.pumpSpeedPercent / 100)),
    coolant: r.loops.map(loop => clamp01((loop.hotLegC - 290) / 50)),
    levels: [...r.loops.map(loop => clamp01(loop.steamGeneratorLevelPercent / 100)), clamp01(r.pressurizer.levelPercent / 100)],
    shaft: Math.max(clamp01(r.secondary.generatorMw / 700), r.secondary.turbineTripped ? 0 : steam * clamp01(r.secondary.turbineValvePercent / 100)),
    steam,
    spray: clamp01(r.pressurizer.sprayPercent / 100),
    relief: Number(r.pressurizer.reliefOpen),
    vent: Math.max(clamp01(r.secondary.steamDumpPercent / 100), Number(r.secondary.steamReliefOpen)),
  };
}

/** Keeps every geometry, material and texture the scene makes, so dispose can free them. */
function tracker() {
  const list = [];
  return {
    add(resource) {
      list.push(resource);
      return resource;
    },
    disposeAll() {
      for (const resource of list) resource.dispose();
      list.length = 0;
    },
  };
}

/**
 * Joins indexed geometries into one, each moved by its matrix. Normals move
 * with the matrix; the UVs are copied as they are.
 */
function joinGeometries(entries, track) {
  let vertexCount = 0;
  let indexCount = 0;
  for (const { geometry } of entries) {
    vertexCount += geometry.attributes.position.count;
    indexCount += geometry.index.count;
  }
  const position = new Float32Array(vertexCount * 3);
  const normal = new Float32Array(vertexCount * 3);
  const uv = new Float32Array(vertexCount * 2);
  const index = new Uint32Array(indexCount);
  const v = new THREE.Vector3();
  const normalMatrix = new THREE.Matrix3();
  let vo = 0;
  let io = 0;
  for (const { geometry, matrix } of entries) {
    const p = geometry.attributes.position;
    const n = geometry.attributes.normal;
    const t = geometry.attributes.uv;
    normalMatrix.getNormalMatrix(matrix);
    for (let i = 0; i < p.count; i++) {
      v.fromBufferAttribute(p, i).applyMatrix4(matrix);
      position.set([v.x, v.y, v.z], (vo + i) * 3);
      v.fromBufferAttribute(n, i).applyMatrix3(normalMatrix).normalize();
      normal.set([v.x, v.y, v.z], (vo + i) * 3);
      if (t) {
        uv[(vo + i) * 2] = t.getX(i);
        uv[(vo + i) * 2 + 1] = t.getY(i);
      }
    }
    const idx = geometry.index;
    for (let i = 0; i < idx.count; i++) index[io + i] = idx.getX(i) + vo;
    vo += p.count;
    io += idx.count;
  }
  const out = new THREE.BufferGeometry();
  out.setAttribute('position', new THREE.BufferAttribute(position, 3));
  out.setAttribute('normal', new THREE.BufferAttribute(normal, 3));
  out.setAttribute('uv', new THREE.BufferAttribute(uv, 2));
  out.setIndex(new THREE.BufferAttribute(index, 1));
  return track.add(out);
}

/** True when an object, or one of its parents up to root, is marked as moving. */
function isAnimated(object, root) {
  for (let o = object; o; o = o.parent) {
    if (o.userData.animated) return true;
    if (o === root) break;
  }
  return false;
}

/**
 * Joins every static mesh under root into one mesh per material, so the scene
 * draws each material once. Meshes marked animated, and instanced meshes, stay
 * as they are.
 */
export function mergeStatic(root, track) {
  root.updateMatrixWorld(true);
  const byMaterial = new Map();
  const found = [];
  root.traverse((object) => {
    if (!(object instanceof THREE.Mesh) || object instanceof THREE.InstancedMesh) return;
    if (isAnimated(object, root)) return;
    found.push(object);
    const key = `${object.material.uuid}:${object.castShadow}:${object.receiveShadow}:${object.renderOrder}`;
    const batch = byMaterial.get(key) ?? { material: object.material, castShadow: object.castShadow,
      receiveShadow: object.receiveShadow, renderOrder: object.renderOrder, entries: [] };
    batch.entries.push({ geometry: object.geometry, matrix: object.matrixWorld.clone() });
    byMaterial.set(key, batch);
  });
  for (const mesh of found) mesh.removeFromParent();
  for (const { material, castShadow, receiveShadow, renderOrder, entries } of byMaterial.values()) {
    const mesh = new THREE.Mesh(joinGeometries(entries, track), material);
    Object.assign(mesh, { castShadow, receiveShadow, renderOrder });
    root.add(mesh);
  }
}

const dummy = new THREE.Object3D();
function place(mesh, index, at, scale = [1, 1, 1], rotation = [0, 0, 0]) {
  dummy.position.set(...at); dummy.scale.set(...scale); dummy.rotation.set(...rotation);
  dummy.updateMatrix(); mesh.setMatrixAt(index, dummy.matrix);
  mesh.instanceMatrix.needsUpdate = true;
}

export function createPlantScene({ theme, reducedMotion, environment }) {
  const resources = tracker();
  const colors = { ...theme };
  const scene = new THREE.Scene();
  scene.environment = environment;
  const camera = new THREE.PerspectiveCamera(64, 1, 0.08, 38);
  const cctvCamera = new THREE.PerspectiveCamera(62, 16 / 9, 0.08, 30);
  cctvCamera.position.set(5.8, 2.5, 6.8);
  cctvCamera.lookAt(1.5, 1.9, 0);
  cctvCamera.layers.set(1);
  const lighting = createLighting(THREE, scene, colors, true);
  // Interior fixtures light the equipment without a shadow pass through the roof.
  scene.traverse(object => {
    if (object.isLight) { object.layers.enableAll(); object.castShadow = false; }
  });
  const make = (role, token, options) => resources.add(createMaterial(THREE, colors, role, token, options));
  const mat = {
    wall: make('concrete', 'sunken'), steel: make('paintedSteel', 'steel'),
    metal: make('brushedMetal', 'metal'), ink: make('rubber', 'ink'),
    face: make('paintedSteel', 'raised'), accent: make('paintedSteel', 'accent'),
    warning: make('paintedSteel', 'warning'), water: make('paintedSteel', 'coldCoolant'),
    steam: make('concrete', 'steam', { transparent: true, opacity: 0.58, depthWrite: false }),
    lit: make('lamp', 'lampGlow'), off: make('lamp', 'lampOff'),
    fixture: make('lamp', 'plantKey', { emissiveIntensity: 3 }),
    coolant: [make('paintedSteel', 'coldCoolant'), make('paintedSteel', 'coldCoolant')],
  };
  const cold = new THREE.Color(), hot = new THREE.Color();
  const cube = resources.add(new THREE.BoxGeometry(1, 1, 1));
  const tube = resources.add(new THREE.CylinderGeometry(1, 1, 1, 16));
  const sphere = resources.add(new THREE.SphereGeometry(1, 12, 8));
  const plane = resources.add(new THREE.PlaneGeometry(1, 1));
  const reactor = new THREE.Group(), hall = new THREE.Group();
  reactor.name = 'Containment operating deck'; hall.name = 'Turbine hall';
  scene.add(reactor, hall);
  reactor.visible = hall.visible = false;
  const fixtures = [], labels = [], gauges = [], levels = [], pipeRuns = [];
  const obstacles = { reactor: [], turbine: [] };
  function solid(parent, geometry, material, at, scale, rotation = [0, 0, 0]) {
    const mesh = new THREE.Mesh(geometry, material);
    mesh.position.set(...at); mesh.scale.set(...scale); mesh.rotation.set(...rotation);
    parent.add(mesh); return mesh;
  }
  const box = (parent, size, material, at) => solid(parent, cube, material, at, size);
  const cylinder = (parent, radius, height, material, at, rotation) => solid(parent, tube, material, at, [radius, height, radius], rotation);
  function instances(parent, geometry, material, count, name) {
    const mesh = new THREE.InstancedMesh(geometry, material, count);
    mesh.name = name; mesh.frustumCulled = false; parent.add(mesh); return mesh;
  }
  function block(room, x, z, width, depth) {
    obstacles[room].push({ minX: x - width / 2, maxX: x + width / 2, minZ: z - depth / 2, maxZ: z + depth / 2 });
  }
  function label(parent, text, at, width = 1.6, height = 0.4, gauge = null) {
    labels.push({ parent, text, at, width, height, gauge });
  }
  function pipe(parent, points, radius, material) {
    pipeRuns.push({ parent, points, radius, material });
  }
  function railing(parent, x, z, length) {
    box(parent, [length, 0.06, 0.06], mat.warning, [x, 1.05, z]);
    box(parent, [length, 0.04, 0.04], mat.metal, [x, 0.5, z]);
    for (let dx = -length / 2; dx <= length / 2 + 0.01; dx += length / Math.ceil(length / 1.5))
      box(parent, [0.06, 1.1, 0.06], mat.metal, [x + dx, 0.55, z]);
  }
  function building(parent, room, x, width, depth, height, floorY = 0) {
    box(parent, [width, 0.3, depth], mat.wall, [x, floorY - 0.15, 0]);
    box(parent, [width, height - floorY, 0.3], mat.wall, [x, (height + floorY) / 2, -depth / 2]);
    box(parent, [width, height - floorY, 0.3], mat.wall, [x, (height + floorY) / 2, depth / 2]);
    for (const side of [-1, 1]) {
      box(parent, [0.3, height - floorY, depth], mat.wall, [x + side * width / 2, (height + floorY) / 2, 0]);
      block(room, x + side * width / 2, 0, 0.3, depth);
      block(room, x, side * depth / 2, width, 0.3);
    }
    // Roof panels leave a vent slot above the service aisle.
    for (const side of [-1, 1]) box(parent, [width, 0.25, depth / 2 - 0.6], mat.steel, [x, height, side * (depth / 4 + 0.3)]);
    for (let z = -depth / 2 + 1; z < depth / 2; z += 4) {
      for (const side of [-1, 1]) {
        box(parent, [0.3, height - floorY, 0.35], mat.metal, [x + side * (width / 2 - 0.35), (height + floorY) / 2, z]);
        box(parent, [width / 2 - 0.4, 0.24, 0.2], mat.metal, [x + side * width / 4, height - 0.8, z]);
        box(parent, [1.8, 0.15, 0.8], mat.ink, [x + side * width / 4, height - 1, z]);
        box(parent, [1.65, 0.04, 0.65], mat.fixture, [x + side * width / 4, height - 1.09, z]);
      }
    }
    for (const z of [-4, 3]) {
      const light = new THREE.PointLight(colors.plantKey, 100, 19, 2);
      light.position.set(x, height - 2, z); parent.add(light); fixtures.push(light);
    }
    // Floor seams and a marked walking aisle establish the scale.
    for (let z = -depth / 2 + 1; z < depth / 2; z += 2)
      box(parent, [width - 0.4, 0.008, 0.018], mat.metal, [x, floorY + 0.006, z]);
  }
  function gauge(parent, room, key, text, at) {
    const [x, y, z] = at;
    cylinder(parent, 0.045, y, mat.metal, [x, y / 2, z - 0.05]);
    box(parent, [0.34, 0.06, 0.3], mat.metal, [x, 0.03, z - 0.05]);
    block(room, x, z, 0.48, 0.35);
    const g = { parent, key, text, at, fraction: 0, pair: null };
    gauges.push(g); label(parent, text, [x, y, z + 0.07], 0.85, 0.85, g);
    return g;
  }
  function sightLevel(parent, x, z, height) {
    box(parent, [0.2, height, 0.12], mat.ink, [x, height / 2 + 0.35, z]);
    const fill = box(parent, [0.1, 1, 0.04], mat.water, [x, 0.35, z + 0.08]);
    fill.geometry = resources.add(cube.clone()); fill.geometry.translate(0, 0.5, 0);
    fill.userData.animated = true; levels.push({ fill, height });
    for (let i = 0; i <= 5; i++) box(parent, [0.08, 0.02, 0.03], mat.face, [x + 0.06, 0.35 + height * i / 5, z + 0.09]);
  }

  building(reactor, 'reactor', 0, 18, 20, 9);
  for (const x of [-1.1, 1.1]) box(reactor, [0.045, 0.01, 4.3], mat.warning, [x, 0.01, 5.5]);
  label(reactor, 'CONTAINMENT / OPERATING DECK', [0, 6.8, -9.82], 7, 0.65);
  label(reactor, 'WASD / arrows to walk. Drag to look.', [0, 5.95, -9.81], 5.8, 0.4);
  // The vessel extends below the deck. The head and drive housings stand above it.
  cylinder(reactor, 1.65, 1.4, mat.metal, [0, -0.2, -2]);
  solid(reactor, sphere, mat.steel, [0, 0.55, -2], [1.65, 0.7, 1.65]);
  cylinder(reactor, 1.8, 0.16, mat.metal, [0, 0.6, -2]);
  block('reactor', 0, -2, 4.1, 4.1);
  const rodPositions = [];
  for (let x = -2; x <= 2; x++) for (let z = -2; z <= 2; z++) {
    if (Math.abs(x) === 2 && Math.abs(z) === 2) continue;
    rodPositions.push([x * 0.48, z * 0.48 - 2]);
  }
  const housings = instances(reactor, tube, mat.metal, rodPositions.length, 'CRDM housings');
  const rods = instances(reactor, tube, mat.accent, rodPositions.length, 'Rod stems');
  const collars = instances(reactor, tube, mat.warning, rodPositions.length, 'Rod position collars');
  const rodLights = [mat.lit, mat.off].map((material, i) => instances(reactor, sphere, material, rodPositions.length * 5, i ? 'Rod lights off' : 'Rod lights on'));
  rodPositions.forEach(([x, z], i) => place(housings, i, [x, 1.95, z], [0.13, 1.4, 0.13]));
  label(reactor, 'REACTOR HEAD / ROD POSITION', [0, 0.62, -0.16], 2.6, 0.3);

  const pumps = [];
  for (const [i, x] of [-4.5, 4.5].entries()) {
    cylinder(reactor, 1.05, 5.7, mat.steel, [x, 3.15, -5]);
    solid(reactor, sphere, mat.metal, [x, 6, -5], [1.05, 0.8, 1.05]);
    cylinder(reactor, 1.16, 0.18, mat.metal, [x, 1.1, -5]);
    cylinder(reactor, 1.16, 0.18, mat.metal, [x, 4.7, -5]);
    block('reactor', x, -5, 2.5, 2.5);
    sightLevel(reactor, x + 0.5, -3.93, 3.8);
    label(reactor, `STEAM GENERATOR ${i ? 'B' : 'A'}`, [x, 4.3, -3.93], 1.9, 0.35);
    pipe(reactor, [[x, 6.7, -5], [x, 7.3, -5], [x, 7.3, -9.8]], 0.23, mat.metal);
    const px = i ? 3.7 : -3.7;
    box(reactor, [1.5, 0.18, 1.5], mat.steel, [px, 0.09, 1.3]);
    for (const dx of [-0.5, 0.5]) box(reactor, [0.14, 1.25, 0.8], mat.metal, [px + dx, 0.75, 1.3]);
    cylinder(reactor, 0.46, 1.05, mat.steel, [px, 1.45, 1.0], [HALF_PI, 0, 0]);
    cylinder(reactor, 0.58, 0.12, mat.metal, [px, 1.45, 1.53], [HALF_PI, 0, 0]);
    block('reactor', px, 1.3, 1.9, 2.2);
    const rotor = new THREE.Group(); rotor.name = `Pump ${i ? 'B' : 'A'} fan`; rotor.userData.animated = true;
    rotor.position.set(px, 1.45, 1.83); reactor.add(rotor);
    cylinder(rotor, 0.16, 0.7, mat.metal, [0, 0, -0.18], [HALF_PI, 0, 0]);
    cylinder(rotor, 0.25, 0.18, mat.warning, [0, 0, -0.12], [HALF_PI, 0, 0]);
    const blades = instances(rotor, cube, mat.accent, 5, 'Fan blades');
    for (let b = 0; b < 5; b++) {
      const a = b * TAU / 5;
      place(blades, b, [Math.sin(a) * 0.31, Math.cos(a) * 0.31, 0.13], [0.15, 0.48, 0.055], [0, 0, -a]);
    }
    // One pale blade makes direction and coastdown visible at low CCTV resolution.
    box(rotor, [0.15, 0.48, 0.06], mat.face, [0, 0.31, 0.14]);
    const lamp = solid(reactor, sphere, mat.off, [px + 0.6, 1.9, 1.7], [0.09, 0.09, 0.09]);
    lamp.userData.animated = true; pumps.push({ rotor, lamp });
    label(reactor, `RCP ${i ? 'B' : 'A'} / MOTOR`, [px, 0.46, 2.08], 1.5, 0.3);
    pipe(reactor, [[Math.sign(x) * 1.4, 0.75, -2], [x, 0.75, -2], [x, 0.75, -4]], 0.24, mat.coolant[i]);
    pipe(reactor, [[x, 0.45, -5], [px + Math.sign(x), 0.45, -5], [px + Math.sign(x), 0.45, 1.3], [px, 0.45, 1.3], [Math.sign(x) * 1.4, 0.45, -2]], 0.2, mat.coolant[i]);
    gauge(reactor, 'reactor', `hot_leg:${i ? 'b' : 'a'}`, `HOT LEG ${i ? 'B' : 'A'}`, [px + (i ? 1 : -1), 1.35, 2.6]);
  }
  cylinder(reactor, 0.75, 4.6, mat.steel, [-6.5, 2.65, -0.5]);
  solid(reactor, sphere, mat.metal, [-6.5, 4.95, -0.5], [0.75, 0.55, 0.75]);
  block('reactor', -6.5, -0.5, 2, 2);
  sightLevel(reactor, -6.5, 0.28, 3.5);
  label(reactor, 'PRESSURIZER', [-6.5, 4.25, 0.28], 1.5, 0.35);
  pipe(reactor, [[-6.5, 0.5, -0.5], [-6.5, 0.5, -2], [-1.5, 0.5, -2]], 0.15, mat.metal);
  pipe(reactor, [[-6.5, 5.5, -0.5], [-6.5, 6.4, -0.5]], 0.12, mat.metal);
  // A small open spray sight chamber sits beside the pressure vessel.
  pipe(reactor, [[-6.5, 5.1, -0.5], [-5.45, 5.1, -0.5], [-5.45, 4.6, -0.5]], 0.08, mat.metal);
  box(reactor, [0.5, 1.3, 0.08], mat.ink, [-5.45, 3.95, -0.65]);
  label(reactor, 'SPRAY', [-5.45, 3.08, -0.4], 0.8, 0.25);
  const spray = instances(reactor, sphere, mat.water, 8, 'Pressurizer spray');
  const relief = instances(reactor, sphere, mat.steam, 6, 'Pressurizer relief');
  gauge(reactor, 'reactor', 'pressurizer_pressure', 'PRESSURIZER', [-6.4, 1.35, 1.35]);
  gauge(reactor, 'reactor', 'core_exit_temperature', 'CORE EXIT', [1.9, 1.35, -0.05]);
  const craneRing = resources.add(new THREE.TorusGeometry(7.8, 0.12, 8, 64));
  solid(reactor, craneRing, mat.metal, [0, 7.5, 0], [1, 1, 1], [HALF_PI, 0, 0]);
  for (const z of [-0.55, 0.55]) box(reactor, [15.4, 0.5, 0.25], mat.warning, [0, 7.75, z - 2.5]);
  box(reactor, [1.3, 0.55, 1.4], mat.steel, [1.4, 7.95, -2.5]);
  cylinder(reactor, 0.025, 2.1, mat.ink, [1.4, 6.6, -2.5]);
  solid(reactor, resources.add(new THREE.TorusGeometry(0.18, 0.045, 6, 12, Math.PI * 1.5)), mat.metal, [1.4, 5.5, -2.5], [1, 1, 1]);

  building(hall, 'turbine', HALL_X, 28, 18, 8.5, -3);
  // The operating walkway overlooks the condenser well beside the train.
  box(hall, [27.6, 0.3, 3.25], mat.wall, [HALL_X, -0.15, 7.125]);
  box(hall, [6.8, 0.3, 2.25], mat.wall, [HALL_X - 10.4, -0.15, 4.375]);
  box(hall, [13.8, 0.3, 2.25], mat.wall, [HALL_X + 6.9, -0.15, 4.375]);
  box(hall, [22, 0.5, 4], mat.steel, [HALL_X, -0.25, -1]);
  for (const x of [-9, -3, 3, 9]) box(hall, [0.8, 2.5, 3], mat.wall, [HALL_X + x, -1.75, -1]);
  for (const x of [-12, 12]) box(hall, [3, 0.3, 12], mat.wall, [HALL_X + x, -0.15, -1]);
  block('turbine', HALL_X, -2, 22, 10.5);
  block('turbine', HALL_X, -8, 28, 2);
  block('turbine', HALL_X - 3.5, 4.375, 7, 2.25);
  for (const x of [-12, 12]) block('turbine', HALL_X + x, -3, 2.5, 5);
  railing(hall, HALL_X - 9, 3.3, 4);
  railing(hall, HALL_X + 5.5, 3.3, 11);
  railing(hall, HALL_X - 3.5, 5.5, 7);
  for (const x of [-7, 0]) {
    for (const y of [0.5, 1.05]) box(hall, [0.06, 0.06, 2.2], mat.metal, [HALL_X + x, y, 4.4]);
  }
  for (const z of [5.9, 8]) box(hall, [26, 0.01, 0.045], mat.warning, [HALL_X, 0.01, z]);
  label(hall, 'TURBINE HALL / OPERATING DECK', [HALL_X, 6.9, -8.82], 9, 0.65);
  const train = [
    { x: -7.5, radius: 0.8, length: 2.4, text: 'HP TURBINE' },
    { x: -3.8, radius: 1.3, length: 3.4, text: 'LP TURBINE' },
    { x: 0.3, radius: 1.3, length: 3.4, text: 'LP TURBINE' },
    { x: 6.4, radius: 1.05, length: 4, text: 'GENERATOR' },
  ];
  for (const c of train) {
    cylinder(hall, c.radius, c.length, mat.steel, [HALL_X + c.x, 1.4, -0.7], [0, 0, HALF_PI]);
    for (const dx of [-c.length / 2, 0, c.length / 2]) cylinder(hall, c.radius + 0.06, 0.12, mat.metal, [HALL_X + c.x + dx, 1.4, -0.7], [0, 0, HALF_PI]);
    box(hall, [c.length, 0.4, c.radius * 1.8], mat.metal, [HALL_X + c.x, 0.2, -0.7]);
    label(hall, c.text, [HALL_X + c.x, 1.5, c.radius - 0.6], Math.min(c.length, 2.5), 0.38);
  }
  const shaft = new THREE.Group(); shaft.name = 'Turbine generator shaft'; shaft.userData.animated = true;
  shaft.position.set(HALL_X, 1.4, -0.7); hall.add(shaft);
  cylinder(shaft, 0.14, 19, mat.metal, [0, 0, 0], [0, 0, HALF_PI]);
  const shaftBands = instances(shaft, cube, mat.warning, 8, 'Coupling marks');
  for (const [i, x] of [-5.85, -1.75, 3.2, 8.9].entries()) {
    cylinder(shaft, 0.35, 0.45, mat.metal, [x, 0, 0], [0, 0, HALF_PI]);
    place(shaftBands, i * 2, [x, 0.32, 0], [0.46, 0.09, 0.13]);
    place(shaftBands, i * 2 + 1, [x, -0.32, 0], [0.46, 0.09, 0.13]);
  }
  // The shaft is exposed between the last turbine and generator.
  label(hall, 'EXPOSED COUPLING', [HALL_X + 3.2, 0.5, 0.3], 1.8, 0.28);
  box(hall, [9, 1.9, 3.1], mat.metal, [HALL_X - 1.7, -1.8, 0.9]);
  box(hall, [7.8, 0.8, 1.7], mat.steel, [HALL_X - 1.7, -0.5, 0]);
  label(hall, 'CONDENSER', [HALL_X - 1.7, -1.3, 2.47], 3, 0.45);
  for (const x of [-5, 1.4]) pipe(hall, [[HALL_X + x, -2, 2.3], [HALL_X + x, -2, 3], [HALL_X + x, -2, 8.8]], 0.25, mat.water);
  const steamPoints = [[HALL_X - 11, 5.4, -7], [HALL_X - 11, 5.4, 0.8], [HALL_X - 7.5, 5.4, 0.8], [HALL_X - 7.5, 2.2, 0.8]];
  pipe(hall, steamPoints, 0.25, mat.metal);
  pipe(hall, [[HALL_X - 9.5, 5.4, -7], [HALL_X - 9.5, 4.8, -0.2], [HALL_X - 7.5, 4.8, -0.2], [HALL_X - 7.5, 2.2, -0.2]], 0.25, mat.metal);
  const steamPath = new THREE.CurvePath();
  steamPoints.slice(1).forEach((p, i) => steamPath.add(new THREE.LineCurve3(new THREE.Vector3(...steamPoints[i]), new THREE.Vector3(...p))));
  const steam = instances(hall, sphere, mat.steam, 12, 'Main steam flow');
  pipe(hall, [[HALL_X - 7.5, 5.4, 0.8], [HALL_X + 5, 5.4, 0.8], [HALL_X + 5, 6.6, 0]], 0.18, mat.metal);
  box(hall, [2, 0.15, 1.1], mat.metal, [HALL_X + 5, 8.4, 0]);
  label(hall, 'STEAM DUMP / ROOF VENT', [HALL_X + 4, 5.9, 1.05], 4, 0.4);
  const vent = instances(hall, sphere, mat.steam, 6, 'Roof vent plume');
  gauge(hall, 'turbine', 'steam_pressure', 'MAIN STEAM', [HALL_X - 8, 1.35, 3.6]);
  gauge(hall, 'turbine', 'condenser_pressure', 'CONDENSER VACUUM', [HALL_X - 1.8, 1.35, 5.7]);
  pipe(hall, [[HALL_X - 1.8, -1, 2.5], [HALL_X - 1.8, 0.1, 5.7], [HALL_X - 1.8, 1.2, 5.7]], 0.025, mat.metal);
  gauge(hall, 'turbine', 'generator_output', 'GENERATOR', [HALL_X + 6.4, 1.35, 3.6]);

  // Shared pipe geometry is instanced once per room and material.
  for (const parent of [reactor, hall]) for (const material of new Set(pipeRuns.filter(run => run.parent === parent).map(run => run.material))) {
    const runs = pipeRuns.filter(run => run.parent === parent && run.material === material);
    const segments = runs.flatMap(run => run.points.slice(1).map((p, i) => ({ a: run.points[i], b: p, radius: run.radius })));
    const pipes = instances(parent, tube, material, segments.length, 'Pipe segments');
    segments.forEach(({ a, b, radius }, i) => {
      const start = new THREE.Vector3(...a), end = new THREE.Vector3(...b), direction = end.clone().sub(start);
      dummy.position.copy(start).add(end).multiplyScalar(0.5);
      dummy.scale.set(radius, direction.length(), radius);
      dummy.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction.normalize());
      dummy.updateMatrix(); pipes.setMatrixAt(i, dummy.matrix);
    });
    pipes.instanceMatrix.needsUpdate = true;
    const bends = runs.flatMap(run => run.points.slice(1, -1).map(at => ({ at, radius: run.radius })));
    const joints = instances(parent, sphere, material, bends.length, 'Pipe bends');
    bends.forEach(({ at, radius }, i) => place(joints, i, at, [radius, radius, radius]));
  }

  const canvas = document.createElement('canvas');
  canvas.width = 2048; canvas.height = 512 * Math.ceil(labels.length / 4);
  const texture = resources.add(new THREE.CanvasTexture(canvas));
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.generateMipmaps = false; texture.minFilter = THREE.LinearFilter;
  const textMaterial = resources.add(new THREE.MeshBasicMaterial({ map: texture, toneMapped: false }));
  labels.forEach((entry, i) => {
    const geometry = resources.add(plane.clone()), uv = geometry.attributes.uv;
    for (let v = 0; v < uv.count; v++) {
      uv.setXY(v, (uv.getX(v) + i % 4) / 4, (uv.getY(v) + Math.ceil(labels.length / 4) - 1 - Math.floor(i / 4)) / Math.ceil(labels.length / 4));
    }
    solid(entry.parent, geometry, textMaterial, entry.at, [entry.width, entry.height, 1]);
  });
  const needleGeometry = resources.add(new THREE.BoxGeometry(0.018, 0.17, 0.014));
  needleGeometry.translate(0, 0.075, 0);
  const gaugeMeshes = [reactor, hall].map(parent => {
    const local = gauges.filter(g => g.parent === parent);
    const cases = instances(parent, tube, mat.metal, local.length, 'Field gauge cases');
    const needles = instances(parent, needleGeometry, mat.ink, local.length, 'Field gauge needles');
    local.forEach((g, i) => {
      place(cases, i, [g.at[0], g.at[1] + 0.1, g.at[2]], [0.25, 0.12, 0.25], [HALF_PI, 0, 0]);
    });
    return { local, needles };
  });
  const forcedColors = globalThis.matchMedia?.('(forced-colors: active)');
  function paintLabels() {
    const ctx = canvas.getContext('2d');
    const background = forcedColors?.matches ? 'Canvas' : colors.raised;
    const foreground = forcedColors?.matches ? 'CanvasText' : colors.ink;
    ctx.fillStyle = background; ctx.fillRect(0, 0, canvas.width, canvas.height);
    labels.forEach((entry, i) => {
      ctx.save(); ctx.translate((i % 4) * 512, Math.floor(i / 4) * 512); ctx.fillStyle = foreground; ctx.strokeStyle = foreground;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      if (entry.gauge) {
        const g = entry.gauge;
        ctx.lineWidth = 3;
        for (let tick = 0; tick <= 8; tick++) {
          const a = Math.PI * 0.75 - Math.PI * 1.5 * tick / 8;
          ctx.beginPath(); ctx.moveTo(256 - Math.sin(a) * 120, 194 - Math.cos(a) * 120);
          ctx.lineTo(256 - Math.sin(a) * 137, 194 - Math.cos(a) * 137); ctx.stroke();
        }
        ctx.font = '24px system-ui, sans-serif';
        ctx.fillText(g.pair ? String(g.pair.range[0]) : '—', 135, 320);
        ctx.fillText(g.pair ? String(g.pair.range[1]) : '—', 377, 320);
        ctx.font = 'bold 27px system-ui, sans-serif'; ctx.fillText(entry.text, 256, 398, 490);
        ctx.font = '32px system-ui, sans-serif'; ctx.fillText(g.pair ? formatValue(g.pair.trueValue, g.pair.unit) : 'Awaiting snapshot', 256, 468, 490);
      } else {
        ctx.scale(0.25, 1);
        ctx.font = 'bold 144px system-ui, sans-serif'; ctx.fillText(entry.text, 1024, 256, 1960);
      }
      ctx.restore();
    });
    texture.needsUpdate = true;
  }
  function applyColors() {
    lighting.setTheme(colors);
    for (const material of Object.values(mat).flat()) applyMaterialPalette(material, colors);
    setIndicator(mat.lit, colors, { lit: true }); setIndicator(mat.off, colors, { lit: false });
    mat.fixture.emissive.set(colors.plantKey);
    cold.set(colors.coldCoolant); hot.set(colors.hotCoolant);
    fixtures.forEach(light => light.color.set(colors.plantKey));
    scene.background = new THREE.Color(colors.sunken); paintLabels();
  }
  forcedColors?.addEventListener('change', paintLabels);
  applyColors();
  for (const [parent, layer] of [[reactor, 1], [hall, 2]]) {
    mergeStatic(parent, resources);
    parent.traverse(object => object.layers.set(layer));
  }

  let latest = null, targets = null, shown = null, clock = 0, steamPhase = 0, currentView = 'reactor';
  let moving = false;
  function ease(value, target, k) {
    if (Math.abs(value - target) < 0.0001) return target;
    moving = true; return value + (target - value) * k;
  }
  function animate(dt) {
    if (!latest) return false;
    dt = Math.max(0, Math.min(0.25, dt));
    const reduced = reducedMotion(), k = reduced ? 1 : 1 - Math.exp(-dt / 0.22);
    moving = false;
    for (const key of Object.keys(targets)) {
      if (Array.isArray(targets[key])) shown[key] = shown[key].map((v, i) => ease(v, targets[key][i], k));
      else shown[key] = ease(shown[key], targets[key], k);
    }
    if (!reduced) { clock += dt; steamPhase = (steamPhase + dt * shown.steam * 0.25) % 1; }
    rodPositions.forEach(([x, z], i) => {
      const fraction = i < 13 ? shown.rods : shown.shutdown;
      place(rods, i, [x, 1.45 + fraction * 1.6, z], [0.055, 1.5, 0.055]);
      place(collars, i, [x, 1.55 + fraction * 1.6, z], [0.17, 0.12, 0.17]);
      const trueFraction = i < 13 ? targets.rods : targets.shutdown;
      for (let n = 0; n < 5; n++) {
        const index = i * 5 + n;
        rodLights.forEach((mesh, state) => {
          const lit = trueFraction >= n / 4;
          const size = lit === (state === 0) ? 0.055 : 0;
          place(mesh, index, [x, 1.45 + n * 0.38, z + 0.15], [size, size, size]);
        });
      }
    });
    levels.forEach(({ fill, height }, i) => { fill.scale.y = Math.max(0.0001, shown.levels[i] * height); });
    pumps.forEach((pump, i) => {
      // Pump status switches the lamp. Speed alone drives the coastdown.
      pump.lamp.material = latest.loops[i].pumpRunning ? mat.lit : mat.off;
      if (!reduced) pump.rotor.rotation.z -= targets.pumps[i] * SPIN * dt;
      mat.coolant[i].color.copy(cold).lerp(hot, shown.coolant[i]);
    });
    if (!reduced) shaft.rotation.x += targets.shaft * SPIN * dt;
    spray.visible = targets.spray > 0;
    relief.visible = targets.relief > 0;
    steam.visible = targets.steam > 0;
    vent.visible = targets.vent > 0;
    for (let i = 0; i < spray.count; i++) {
      const fall = (i / spray.count + clock * 0.8) % 1, size = 0.035 + 0.035 * shown.spray;
      place(spray, i, [-5.45 + Math.sin(i * 2.3) * 0.14, 4.5 - fall * 1.1, -0.45], [size, size * 1.8, size]);
    }
    for (const [mesh, x, y, z, amount] of [[relief, -6.5, 6.5, -0.5, shown.relief], [vent, HALL_X + 5, 6.7, 0, shown.vent]]) {
      for (let i = 0; i < mesh.count; i++) {
        const rise = (i / mesh.count + clock * 0.32) % 1, size = (0.14 + rise * 0.4) * amount;
        place(mesh, i, [x + rise * 0.2, y + rise * 1.6, z], [size, size * 1.4, size]);
      }
    }
    for (let i = 0; i < steam.count; i++) {
      const p = steamPath.getPointAt((i / steam.count + steamPhase) % 1);
      // Puffs run on the pipe surface, where they remain visible outside the steel.
      place(steam, i, [p.x, p.y, p.z + 0.26], [0.075, 0.075, 0.075]);
    }
    gaugeMeshes.forEach(({ local, needles }) => local.forEach((g, i) => {
      const [low, high] = g.pair.range;
      g.fraction = ease(g.fraction, clamp01((g.pair.trueValue - low) / (high - low)), k);
      place(needles, i, [g.at[0], g.at[1] + 0.103, g.at[2] + 0.09], [1, 1, 1], [0, 0, Math.PI * 0.75 - Math.PI * 1.5 * g.fraction]);
    }));
    return !reduced && (moving || targets.pumps.some(v => v > 0) || targets.shaft > 0 || targets.steam > 0 || targets.spray > 0 || targets.relief > 0 || targets.vent > 0);
  }
  function setView(name) {
    const view = VIEWS[name];
    if (!view) throw new Error(`No view named ${name}`);
    currentView = name === 'turbine' ? 'turbine' : 'reactor';
    camera.layers.set(currentView === 'reactor' ? 1 : 2);
    camera.position.set(...view.eye); camera.lookAt(...view.look);
    camera.rotation.order = 'YXZ';
    stopWalking();
  }

  // Input belongs to the shared canvas. No renderer or graphics context is created.
  let inputCanvas = null, sharedRenderer = null, walkFrame = 0, drag = null, lastWalk = 0;
  const keys = new Set(), listeners = [];
  function active() {
    const host = inputCanvas?.closest('[data-view]');
    return host && host.dataset.view === (currentView === 'reactor' ? 'Reactor building' : 'Turbine hall');
  }
  function stopWalking() {
    keys.clear(); drag = null;
    if (walkFrame) cancelAnimationFrame(walkFrame);
    walkFrame = 0;
  }
  function redraw() {
    if (!active() || reducedMotion()) return;
    sharedRenderer.info.reset(); sharedRenderer.render(scene, camera);
  }
  function walkingFrame(now) {
    walkFrame = 0;
    if (!active() || reducedMotion() || !keys.size) return;
    const delta = walkDelta(keys, camera.rotation.y, Math.min(0.05, (now - lastWalk) / 1000)); lastWalk = now;
    const next = walk({ x: camera.position.x, z: camera.position.z }, delta.x, delta.z, obstacles[currentView], 0.28);
    camera.position.set(next.x, 1.7, next.z); redraw();
    walkFrame = requestAnimationFrame(walkingFrame);
  }
  function listen(target, type, callback) {
    target.addEventListener(type, callback); listeners.push(() => target.removeEventListener(type, callback));
  }
  scene.onBeforeRender = renderer => {
    if (inputCanvas) return;
    sharedRenderer = renderer; inputCanvas = renderer.domElement;
    const walkingKeys = new Set(['KeyW', 'KeyA', 'KeyS', 'KeyD', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight']);
    listen(inputCanvas, 'keydown', event => {
      if (!active() || reducedMotion() || !walkingKeys.has(event.code) || event.altKey || event.ctrlKey || event.metaKey) return;
      event.preventDefault(); keys.add(event.code);
      if (!walkFrame) { lastWalk = performance.now(); walkFrame = requestAnimationFrame(walkingFrame); }
    });
    listen(inputCanvas, 'keyup', event => { keys.delete(event.code); });
    listen(inputCanvas, 'blur', stopWalking); listen(window, 'blur', stopWalking);
    listen(inputCanvas, 'pointerdown', event => {
      if (!active() || reducedMotion() || event.button !== 0) return;
      inputCanvas.focus(); inputCanvas.setPointerCapture?.(event.pointerId); drag = { x: event.clientX, y: event.clientY };
    });
    listen(inputCanvas, 'pointermove', event => {
      if (!drag || !active() || reducedMotion()) return;
      const pose = look({ yaw: camera.rotation.y, pitch: camera.rotation.x }, event.clientX - drag.x, event.clientY - drag.y);
      camera.rotation.set(pose.pitch, pose.yaw, 0, 'YXZ'); drag = { x: event.clientX, y: event.clientY }; redraw();
    });
    listen(inputCanvas, 'pointerup', () => { drag = null; });
    listen(inputCanvas, 'pointercancel', stopWalking);
  };
  setView('reactor');
  return {
    scene, camera, cctvCamera, advance: animate, setView,
    update(snapshot) {
      latest = instruments(snapshot); targets = targetsFrom(latest);
      const first = shown === null;
      if (first) shown = structuredClone(targets);
      gauges.forEach(g => {
        g.pair = latest.pairs.find(pair => pair.key === g.key);
        if (first || reducedMotion()) g.fraction = clamp01((g.pair.trueValue - g.pair.range[0]) / (g.pair.range[1] - g.pair.range[0]));
      });
      reactor.visible = hall.visible = true; paintLabels(); animate(0);
      return latest;
    },
    setTheme(next) { Object.assign(colors, next); applyColors(); if (latest) animate(0); },
    dispose() {
      stopWalking(); listeners.forEach(remove => remove()); forcedColors?.removeEventListener('change', paintLabels);
      scene.traverse(object => { if (object.isInstancedMesh) object.dispose(); });
      fixtures.forEach(light => light.dispose()); lighting.dispose();
      scene.onBeforeRender = () => {}; scene.environment = null; scene.clear(); resources.disposeAll();
    },
  };
}

/**
 * A text panel with the same readings as the scene, for a viewer who cannot
 * use the 3D view. Every value is written from the snapshot as it is.
 * Returns update(snapshot) and dispose().
 */
export function createReadingsPanel(container) {
  const section = document.createElement('section');
  section.className = 'plant-readings';
  section.setAttribute('aria-label', 'Plant readings');

  const heading = document.createElement('h2');
  heading.textContent = 'Readings';
  const status = document.createElement('p');
  status.textContent = 'Waiting for the first plant snapshot.';
  const legend = document.createElement('p');
  legend.textContent =
    'Reported is what the instruments show. True is the plant itself. The gap is reported minus true. Diverged means a gap above the limit for its unit, with a fault. Lagging means the same gap with no fault: temperature readings trail fast changes by about three seconds.';

  const table = document.createElement('table');
  const headRow = table.createTHead().insertRow();
  for (const [text, numeric] of [
    ['Point', false],
    ['True', true],
    ['Reported', true],
    ['Gap', true],
    ['State', false],
  ]) {
    const th = document.createElement('th');
    th.scope = 'col';
    th.textContent = text;
    if (numeric) th.className = 'num';
    headRow.append(th);
  }
  const body = table.createTBody();
  let rows = [];

  section.append(heading, status, legend, table);
  container.append(section);

  return {
    update(snapshot) {
      const r = instruments(snapshot);
      if (rows.length !== r.pairs.length) {
        body.replaceChildren();
        rows = r.pairs.map(() => {
          const row = body.insertRow();
          const cells = [];
          for (let i = 0; i < 5; i++) {
            const cell = row.insertCell();
            if (i >= 1 && i <= 3) cell.className = 'num';
            cells.push(cell);
          }
          return cells;
        });
      }
      const seconds = (r.atMs / 1000).toFixed(1);
      status.textContent = r.telemetry.quiet
        ? `Plant time ${seconds} s. Telemetry is quiet: every reading is held at its last value.`
        : `Plant time ${seconds} s. Telemetry is running.`;
      r.pairs.forEach((p, k) => {
        const cells = rows[k];
        const state = stateOf(p);
        cells[0].textContent = p.label;
        cells[1].textContent = formatValue(p.trueValue, p.unit);
        cells[2].textContent = p.reported === null ? 'no reading' : formatValue(p.reported, p.unit);
        cells[3].textContent = p.gap === null ? '' : formatGap(p.gap, p.unit);
        cells[4].textContent = state.text;
        cells[4].className = state.className;
      });
      return r;
    },
    dispose() {
      section.remove();
    },
  };
}

/** The state column: what the flags say, in words. */
function stateOf(p) {
  if (p.frozen && p.diverged) return { text: 'Frozen, diverged', className: 'state-frozen' };
  if (p.frozen) return { text: 'Frozen', className: 'state-frozen' };
  if (p.fault) {
    return p.diverged
      ? { text: 'Diverged', className: 'state-diverged' }
      : { text: `Fault: ${p.fault}, agrees`, className: '' };
  }
  if (p.diverged) return { text: 'Lagging', className: '' };
  return { text: 'Agrees', className: '' };
}
