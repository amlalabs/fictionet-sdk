// Plant interiors use snapshot truth. Motion only interpolates the picture.
import * as THREE from '/vendor/three/build/three.module.js';
import { formatGap, formatValue, instruments } from './instruments.mjs';
import { createMaterial, createLighting, applyMaterialPalette, setIndicator, joinGeometries } from './look.mjs';
import { PLANT_OFFSETS, passageCollisions } from './board-layout.mjs';

const HALF_PI = Math.PI / 2;
const HALL_X = 40;
const SPIN = 9;
const clamp01 = value => Math.max(0, Math.min(1, value));
export const VIEWS = {
  overview: { eye: [0, 1.7, 7.8], look: [0, 2.5, -2] },
  reactor: { eye: [0, 1.7, 7.8], look: [0, 2.5, -2] },
  turbine: { eye: [HALL_X - 9, 1.7, 6.4], look: [HALL_X + 0.5, 2.2, -0.5] },
};

for (const [name, view] of Object.entries(VIEWS)) {
  const offset = PLANT_OFFSETS[name === 'turbine' ? 'turbine' : 'reactor'];
  for (const point of [view.eye, view.look]) {
    point[0] += offset.x;
    point[2] += offset.z;
  }
}

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
    const mesh = new THREE.Mesh(joinGeometries(THREE, entries, track), material);
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

export function createPlantScene({ theme, reducedMotion, environment, anisotropy = 4 }) {
  const resources = tracker();
  const colors = { ...theme };
  const scene = new THREE.Scene();
  scene.environment = environment;
  scene.name = 'Plant interiors';
  const camera = new THREE.PerspectiveCamera(64, 1, 0.08, 38);
  const cctvCamera = new THREE.PerspectiveCamera(62, 16 / 9, 0.08, 30);
  cctvCamera.position.set(5.8, 2.5, 6.8);
  cctvCamera.lookAt(1.5, 1.9, 0);
  cctvCamera.layers.set(1);
  const lighting = createLighting(THREE, scene, colors, true);
  // Interior fixtures light the equipment without a shadow pass through the roof.
  scene.traverse(object => {
    if (object.isLight) {
      object.layers.enableAll();
      object.castShadow = false;
      object.intensity = 0.15;
    }
  });
  const make = (role, token, options) => resources.add(createMaterial(THREE, colors, role, token, options));
  const mat = {
    wall: make('concrete', 'sunken'), steel: make('paintedSteel', 'steel'),
    metal: make('brushedMetal', 'metal'), ink: make('rubber', 'ink'),
    face: make('paintedSteel', 'raised'), accent: make('paintedSteel', 'accent'),
    warning: make('paintedSteel', 'warning'), water: make('paintedSteel', 'coldCoolant'),
    steam: make('concrete', 'steam', { transparent: true, opacity: 0.58, depthWrite: false }),
    lit: make('lamp', 'lampGlow'), off: make('lamp', 'lampOff'),
    rodLight: make('lamp', 'lampGlow', { emissiveIntensity: 2.4 }),
    fixture: make('lamp', 'plantKey', { emissiveIntensity: 3 }),
    coolant: [make('paintedSteel', 'coldCoolant'), make('paintedSteel', 'coldCoolant')],
  };
  const cold = new THREE.Color(), hot = new THREE.Color();
  const cube = resources.add(new THREE.BoxGeometry(1, 1, 1));
  const tube = resources.add(new THREE.CylinderGeometry(1, 1, 1, 16));
  const stemTube = resources.add(new THREE.CylinderGeometry(1, 1, 1, 8));
  const sphere = resources.add(new THREE.SphereGeometry(1, 12, 8));
  const plane = resources.add(new THREE.PlaneGeometry(1, 1));
  const reactor = new THREE.Group(), hall = new THREE.Group();
  reactor.name = 'Containment operating deck'; hall.name = 'Turbine hall';
  scene.add(reactor, hall);
  reactor.visible = hall.visible = false;
  const fixtures = [], labels = [], gauges = [], levels = [], pipeRuns = [];
  const obstacles = { reactor: [], turbine: [], corridor: passageCollisions(7, 11), airlock: passageCollisions(29, 33) };
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
    box(parent, [width + 0.04, height + 0.04, 0.035], mat.metal, [at[0], at[1], at[2] - 0.025]);
    if (!gauge) {
      for (const side of [-1, 1]) box(parent, [0.06, height * 0.7, 0.3], mat.metal,
        [at[0] + side * width * 0.4, at[1], at[2] - 0.18]);
    }
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
    const opening = room === 'reactor' ? 0 : HALL_X - 12;
    for (const side of [-1, 1]) {
      const z = side * depth / 2;
      const open = room === 'turbine' || side === -1;
      if (open) {
        for (const [left, right] of [[x - width / 2, opening - 0.625], [opening + 0.625, x + width / 2]]) {
          box(parent, [right - left, height - floorY, 0.3], mat.wall, [(left + right) / 2, (height + floorY) / 2, z]);
          block(room, (left + right) / 2, z, right - left, 0.3);
        }
        box(parent, [1.25, height - 2.3, 0.3], mat.wall, [opening, (height + 2.3) / 2, z]);
      } else {
        box(parent, [width, height - floorY, 0.3], mat.wall, [x, (height + floorY) / 2, z]);
        block(room, x, z, width, 0.3);
      }
      box(parent, [0.3, height - floorY, depth], mat.wall, [x + side * width / 2, (height + floorY) / 2, 0]);
      block(room, x + side * width / 2, 0, 0.3, depth);
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
    for (const z of [-5, 3]) for (const side of [-1, 1]) {
      const token = room === 'reactor' ? 'coldCoolant' : 'plantKey';
      const intensity = room === 'reactor' ? 100 : 180;
      const light = new THREE.SpotLight(colors[token], intensity, 18, 0.7, 0.65, 2);
      light.position.set(x + side * width / 4, height - 1.15, z);
      light.target.position.set(x + side * width / 4, 0, z);
      light.userData.paletteToken = token;
      light.layers.enableAll();
      parent.add(light, light.target);
      fixtures.push(light);
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
    gauges.push(g);
    label(parent, text, [x, y, z + 0.07], 0.26, 0.26, g);
    return g;
  }
  function sightLevel(parent, x, z, height) {
    box(parent, [0.2, height, 0.12], mat.ink, [x, height / 2 + 0.35, z]);
    levels.push({ at: [x, 0.35, z + 0.08], height });
    for (let i = 0; i <= 5; i++) box(parent, [0.08, 0.02, 0.03], mat.face, [x + 0.06, 0.35 + height * i / 5, z + 0.09]);
  }

  building(reactor, 'reactor', 0, 18, 20, 9);
  for (const x of [-1.1, 1.1]) box(reactor, [0.045, 0.01, 4.3], mat.warning, [x, 0.01, 5.5]);
  label(reactor, 'CONTAINMENT / OPERATING DECK', [0, 6.8, -9.82], 7, 0.65);
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
  const housings = instances(reactor, stemTube, mat.metal, rodPositions.length, 'CRDM housings');
  const rods = instances(reactor, stemTube, mat.accent, rodPositions.length, 'Rod stems');
  const collars = instances(reactor, stemTube, mat.warning, rodPositions.length, 'Rod position collars');
  const rodLightGeometry = resources.add(cube.clone());
  const rodGlow = new THREE.InstancedBufferAttribute(new Float32Array(rodPositions.length * 5), 1);
  rodLightGeometry.setAttribute('instanceGlow', rodGlow);
  mat.rodLight.onBeforeCompile = shader => {
    shader.vertexShader = 'attribute float instanceGlow; varying float vInstanceGlow;\n' + shader.vertexShader;
    shader.vertexShader = shader.vertexShader.replace('#include <color_vertex>',
      '#include <color_vertex>\nvInstanceGlow = instanceGlow;');
    shader.fragmentShader = 'varying float vInstanceGlow;\n' + shader.fragmentShader;
    shader.fragmentShader = shader.fragmentShader.replace('#include <emissivemap_fragment>',
      '#include <emissivemap_fragment>\ntotalEmissiveRadiance *= vColor.rgb * vInstanceGlow;');
  };
  const rodLights = instances(reactor, rodLightGeometry, mat.rodLight, rodPositions.length * 5, 'Rod position lights');
  const rodColor = new THREE.Color();
  rodPositions.forEach(([x, z], i) => place(housings, i, [x, 1.95, z], [0.13, 1.4, 0.13]));
  label(reactor, 'REACTOR HEAD / ROD POSITION', [0, 0.62, -0.16], 2.6, 0.3);

  const pumps = [];
  for (const [i, x] of [-4.5, 4.5].entries()) {
    cylinder(reactor, 0.85, 3.6, mat.steel, [x, 2.1, -5]);
    solid(reactor, resources.add(new THREE.CylinderGeometry(1.25, 0.85, 1, 24)), mat.steel, [x, 4.4, -5], [1, 1, 1]);
    cylinder(reactor, 1.25, 1.5, mat.steel, [x, 5.65, -5]);
    solid(reactor, sphere, mat.metal, [x, 6.4, -5], [1.25, 0.55, 1.25]);
    for (const y of [1.1, 4.9, 6.35]) cylinder(reactor, y < 4 ? 0.94 : 1.3, 0.12, mat.metal, [x, y, -5]);
    block('reactor', x, -5, 2.5, 2.5);
    sightLevel(reactor, x + 0.5, -3.93, 3.8);
    label(reactor, `STEAM GENERATOR ${i ? 'B' : 'A'}`, [x, 5.5, -3.72], 1.9, 0.35);
    pipe(reactor, [[x, 6.7, -5], [x, 7.3, -5], [x, 7.3, -9.8]], 0.23, mat.metal);
    const px = i ? 3.7 : -3.7;
    box(reactor, [1.5, 0.18, 1.5], mat.steel, [px, 0.09, 1.3]);
    cylinder(reactor, 0.65, 0.7, mat.steel, [px, 0.53, 1.3]);
    cylinder(reactor, 0.4, 0.45, mat.metal, [px, 1.05, 1.3]);
    cylinder(reactor, 0.57, 2, mat.steel, [px, 2.6, 1.3]);
    cylinder(reactor, 0.68, 0.42, mat.metal, [px, 3.8, 1.3]);
    for (const y of [1.65, 3.55, 4.05]) cylinder(reactor, 0.67, 0.08, mat.metal, [px, y, 1.3]);
    // The guard has a front inspection opening onto the striped coupling.
    for (const dx of [-0.55, 0.55]) box(reactor, [0.12, 0.58, 1.1], mat.metal, [px + dx, 1.32, 1.3]);
    box(reactor, [1.1, 0.58, 0.12], mat.metal, [px, 1.32, 0.8]);
    block('reactor', px, 1.3, 1.9, 2.2);
    const rotor = new THREE.Group();
    rotor.name = `Pump ${i ? 'B' : 'A'} coupling`;
    rotor.userData.animated = true;
    rotor.position.set(px, 1.32, 1.3);
    reactor.add(rotor);
    const lamp = solid(reactor, sphere, mat.off, [px + 0.6, 1.9, 1.7], [0.06, 0.06, 0.06]);
    lamp.userData.animated = true;
    pumps.push({ rotor, lamp });
    label(reactor, `RCP ${i ? 'B' : 'A'} / MOTOR`, [px, 2.7, 1.88], 0.9, 0.2);
    pipe(reactor, [[Math.sign(x) * 1.4, 0.75, -2], [x, 0.75, -2], [x, 0.75, -4]], 0.24, mat.coolant[i]);
    pipe(reactor, [[x, 0.45, -5], [px + Math.sign(x), 0.45, -5], [px + Math.sign(x), 0.45, 1.3], [px, 0.45, 1.3], [Math.sign(x) * 1.4, 0.45, -2]], 0.2, mat.coolant[i]);
    gauge(reactor, 'reactor', `hot_leg:${i ? 'b' : 'a'}`, `HOT LEG ${i ? 'B' : 'A'}`, [px + (i ? 1 : -1), 1.35, 2.6]);
  }
  cylinder(reactor, 0.75, 4.6, mat.steel, [-6.5, 2.65, -0.5]);
  solid(reactor, sphere, mat.metal, [-6.5, 4.95, -0.5], [0.75, 0.55, 0.75]);
  block('reactor', -6.5, -0.5, 2, 2);
  sightLevel(reactor, -6.5, 0.28, 3.5);
  label(reactor, 'PRESSURIZER', [-6.5, 4.25, 0.28], 1.1, 0.25);
  pipe(reactor, [[-6.5, 0.5, -0.5], [-6.5, 0.5, -2], [-1.5, 0.5, -2]], 0.15, mat.metal);
  pipe(reactor, [[-6.5, 5.5, -0.5], [-6.5, 6.4, -0.5]], 0.12, mat.metal);
  // A small open spray sight chamber sits beside the pressure vessel.
  pipe(reactor, [[-6.5, 5.1, -0.5], [-5.45, 5.1, -0.5], [-5.45, 4.6, -0.5]], 0.08, mat.metal);
  box(reactor, [0.5, 1.3, 0.08], mat.ink, [-5.45, 3.95, -0.65]);
  label(reactor, 'SPRAY', [-5.45, 3.45, -0.59], 0.45, 0.18);
  const droplet = resources.add(new THREE.SphereGeometry(1, 8, 6));
  const spray = instances(reactor, droplet, mat.water, 8, 'Pressurizer spray');
  const relief = instances(reactor, droplet, mat.steam, 6, 'Pressurizer relief');
  const levelGeometry = resources.add(cube.clone().translate(0, 0.5, 0));
  const levelFills = instances(reactor, levelGeometry, mat.water, levels.length, 'Sight glass levels');
  const pumpRotors = instances(reactor, tube, mat.metal, pumps.length, 'Pump couplings');
  const pumpMarks = instances(reactor, cube, mat.warning, pumps.length, 'Pump coupling stripes');
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
  for (const x of [-12, 12]) box(hall, [3, 0.3, 18], mat.wall, [HALL_X + x, -0.15, 0]);
  block('turbine', HALL_X, -2, 22, 10.5);
  block('turbine', HALL_X, -8, 22, 2);
  block('turbine', HALL_X - 3.5, 4.375, 7, 2.25);
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
  box(hall, [1.9, 0.7, 0.2], mat.steel, [HALL_X + 3.2, 0.35, 0.17]);
  label(hall, 'EXPOSED COUPLING', [HALL_X + 3.2, 0.5, 0.3], 1.8, 0.28);
  box(hall, [9, 1.9, 3.1], mat.metal, [HALL_X - 1.7, -1.8, 0.9]);
  box(hall, [7.8, 0.8, 1.7], mat.steel, [HALL_X - 1.7, -0.5, 0]);
  label(hall, 'CONDENSER', [HALL_X - 1.7, -1.3, 2.47], 3, 0.45);
  for (const x of [-5, 1.4]) pipe(hall, [[HALL_X + x, -2, 2.3], [HALL_X + x, -2, 3], [HALL_X + x, -2, 8.8]], 0.25, mat.water);
  const steamPoints = [[HALL_X - 11, 5.4, -7], [HALL_X - 11, 5.4, 0.8], [HALL_X - 7.5, 5.4, 0.8], [HALL_X - 7.5, 2.2, 0.8]];
  pipe(hall, steamPoints, 0.25, mat.metal);
  pipe(hall, [[HALL_X - 9.5, 5.4, -7], [HALL_X - 9.5, 4.8, -0.2], [HALL_X - 7.5, 4.8, -0.2], [HALL_X - 7.5, 2.2, -0.2]], 0.25, mat.metal);
  pipe(hall, [[HALL_X - 7.5, 5.4, 0.8], [HALL_X + 5, 5.4, 0.8], [HALL_X + 5, 6.6, 0]], 0.18, mat.metal);
  box(hall, [2, 0.15, 1.1], mat.metal, [HALL_X + 5, 8.4, 0]);
  label(hall, 'STEAM DUMP / ROOF VENT', [HALL_X + 4, 5.9, -8.82], 4, 0.4);
  const puffCanvas = document.createElement('canvas');
  puffCanvas.width = puffCanvas.height = 64;
  const puffContext = puffCanvas.getContext('2d');
  const gradient = puffContext.createRadialGradient(32, 32, 0, 32, 32, 32);
  gradient.addColorStop(0, colors.lightKey);
  gradient.addColorStop(1, `${colors.lightKey}00`);
  puffContext.fillStyle = gradient;
  puffContext.fillRect(0, 0, 64, 64);
  const puffTexture = resources.add(new THREE.CanvasTexture(puffCanvas));
  const puffMaterial = resources.add(new THREE.SpriteMaterial({ map: puffTexture, color: colors.steam, transparent: true, opacity: 0.35, depthWrite: false }));
  const vent = new THREE.Group();
  vent.name = 'Roof vent plume';
  vent.userData.animated = true;
  hall.add(vent);
  for (let i = 0; i < 6; i++) vent.add(new THREE.Sprite(puffMaterial));
  gauge(hall, 'turbine', 'steam_pressure', 'MAIN STEAM', [HALL_X - 6.5, 1.35, 3.6]);
  gauge(hall, 'turbine', 'steam_flow:a', 'STEAM A FLOW', [HALL_X - 5.9, 1.35, 3.6]);
  gauge(hall, 'turbine', 'steam_flow:b', 'STEAM B FLOW', [HALL_X - 5.3, 1.35, 3.6]);
  gauge(hall, 'turbine', 'condenser_pressure', 'CONDENSER VACUUM', [HALL_X - 1.8, 1.35, 5.7]);
  pipe(hall, [[HALL_X - 1.8, -1, 2.5], [HALL_X - 1.8, 0.1, 5.7], [HALL_X - 1.8, 1.2, 5.7]], 0.025, mat.metal);
  gauge(hall, 'turbine', 'generator_output', 'GENERATOR', [HALL_X + 6.4, 1.35, 3.6]);

  const openTube = resources.add(new THREE.CylinderGeometry(1, 1, 1, 16, 1, true));
  const cap = resources.add(new THREE.CircleGeometry(1, 16).rotateX(-HALF_PI));
  // Pipe walls join the static material batches. Bends cover the internal caps.
  for (const parent of [reactor, hall]) for (const material of new Set(pipeRuns.filter(run => run.parent === parent).map(run => run.material))) {
    const runs = pipeRuns.filter(run => run.parent === parent && run.material === material);
    const segments = runs.flatMap(run => run.points.slice(1).map((p, i) => ({ a: run.points[i], b: p, radius: run.radius })));
    segments.forEach(({ a, b, radius }) => {
      const start = new THREE.Vector3(...a), end = new THREE.Vector3(...b), direction = end.clone().sub(start);
      const mesh = new THREE.Mesh(openTube, material);
      mesh.position.copy(start).add(end).multiplyScalar(0.5);
      mesh.scale.set(radius, direction.length(), radius);
      mesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction.normalize());
      parent.add(mesh);
    });
    for (const run of runs) {
      for (const at of run.points.slice(1, -1)) solid(parent, sphere, material, at, [run.radius, run.radius, run.radius]);
      for (const [end, neighbor] of [[0, 1], [run.points.length - 1, run.points.length - 2]]) {
        const mesh = solid(parent, cap, material, run.points[end], [run.radius, 1, run.radius]);
        const direction = new THREE.Vector3(...run.points[end]).sub(new THREE.Vector3(...run.points[neighbor])).normalize();
        mesh.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction);
      }
    }
  }

  // Paint each plate at its own aspect, then pack it without stretching.
  for (const parent of [reactor, hall]) {
    const local = labels.filter(entry => entry.parent === parent);
    const atlas = document.createElement('canvas');
    atlas.width = 2048;
    let x = 16;
    let y = 16;
    let rowHeight = 0;
    for (const entry of local) {
      const canvas = document.createElement('canvas');
      canvas.height = entry.gauge ? 512 : 128;
      canvas.width = Math.round(canvas.height * entry.width / entry.height);
      if (x + canvas.width + 16 > atlas.width) {
        x = 16;
        y += rowHeight + 32;
        rowHeight = 0;
      }
      Object.assign(entry, { canvas, x, y });
      x += canvas.width + 32;
      rowHeight = Math.max(rowHeight, canvas.height);
    }
    atlas.height = 2 ** Math.ceil(Math.log2(y + rowHeight + 16));
    const texture = resources.add(new THREE.CanvasTexture(atlas));
    texture.colorSpace = THREE.SRGBColorSpace;
    texture.generateMipmaps = true;
    texture.minFilter = THREE.LinearMipmapLinearFilter;
    texture.anisotropy = anisotropy;
    const material = resources.add(new THREE.MeshBasicMaterial({ map: texture, toneMapped: false }));
    for (const entry of local) {
      const geometry = resources.add(plane.clone());
      const uv = geometry.attributes.uv;
      for (let i = 0; i < uv.count; i++) {
        uv.setXY(i, (entry.x + uv.getX(i) * entry.canvas.width) / atlas.width,
          1 - (entry.y + (1 - uv.getY(i)) * entry.canvas.height) / atlas.height);
      }
      solid(parent, geometry, material, entry.at, [entry.width, entry.height, 1]);
      Object.assign(entry, { atlas, texture });
    }
  }
  const needleGeometry = resources.add(new THREE.BoxGeometry(0.006, 0.052, 0.006));
  needleGeometry.translate(0, 0.023, 0);
  const gaugeMeshes = [reactor, hall].map(parent => {
    const local = gauges.filter(g => g.parent === parent);
    const cases = instances(parent, tube, mat.metal, local.length, 'Field gauge cases');
    const needles = instances(parent, needleGeometry, mat.ink, local.length, 'Field gauge needles');
    local.forEach((g, i) => {
      place(cases, i, [g.at[0], g.at[1] + 0.03, g.at[2]], [0.14, 0.12, 0.14], [HALF_PI, 0, 0]);
    });
    return { local, needles };
  });
  const forcedColors = globalThis.matchMedia?.('(forced-colors: active)');
  function paintLabels() {
    const background = forcedColors?.matches ? 'Canvas' : colors.raised;
    const foreground = forcedColors?.matches ? 'CanvasText' : colors.ink;
    labels.forEach(entry => {
      const { canvas, texture } = entry;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = background;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = foreground;
      ctx.strokeStyle = foreground;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      if (entry.gauge) {
        const g = entry.gauge;
        ctx.lineWidth = 3;
        for (let tick = 0; tick <= 8; tick++) {
          const a = Math.PI * 0.75 - Math.PI * 1.5 * tick / 8;
          ctx.beginPath();
          ctx.moveTo(256 - Math.sin(a) * 120, 194 - Math.cos(a) * 120);
          ctx.lineTo(256 - Math.sin(a) * 137, 194 - Math.cos(a) * 137);
          ctx.stroke();
        }
        ctx.font = '24px system-ui, sans-serif';
        ctx.fillText(g.pair ? String(g.pair.range[0]) : '—', 135, 320);
        ctx.fillText(g.pair ? String(g.pair.range[1]) : '—', 377, 320);
        ctx.font = 'bold 27px system-ui, sans-serif';
        ctx.fillText(entry.text, 256, 398, 490);
        ctx.font = '32px system-ui, sans-serif';
        ctx.fillText(g.pair ? formatValue(g.pair.trueValue, g.pair.unit) : 'Awaiting snapshot', 256, 468, 490);
      } else {
        const font = Math.min(80, (canvas.width - 32) / (entry.text.length * 0.65));
        ctx.font = `bold ${font}px system-ui, sans-serif`;
        ctx.fillText(entry.text, canvas.width / 2, canvas.height / 2);
      }
      const atlasContext = entry.atlas.getContext('2d');
      atlasContext.fillStyle = background;
      atlasContext.fillRect(entry.x - 16, entry.y - 16, canvas.width + 32, canvas.height + 32);
      atlasContext.drawImage(canvas, entry.x, entry.y);
      texture.needsUpdate = true;
    });
  }
  function applyColors() {
    lighting.setTheme(colors);
    for (const material of Object.values(mat).flat()) applyMaterialPalette(material, colors);
    setIndicator(mat.lit, colors, { lit: true }); setIndicator(mat.off, colors, { lit: false });
    mat.rodLight.color.setScalar(1);
    mat.rodLight.emissive.setScalar(1);
    mat.fixture.emissive.set(colors.plantKey);
    puffMaterial.color.set(colors.steam);
    cold.set(colors.coldCoolant); hot.set(colors.hotCoolant);
    fixtures.forEach(light => light.color.set(colors[light.userData.paletteToken]));
    scene.background = new THREE.Color(colors.sunken); paintLabels();
  }
  applyColors();
  for (const [parent, layer] of [[reactor, 1], [hall, 2]]) {
    mergeStatic(parent, resources);
    parent.traverse(object => object.layers.set(layer));
  }

  for (const [name, parent] of [['reactor', reactor], ['turbine', hall]]) {
    const offset = PLANT_OFFSETS[name];
    parent.position.set(offset.x, 0, offset.z);
    obstacles[name] = obstacles[name].map(b => ({ minX: b.minX + offset.x, maxX: b.maxX + offset.x,
      minZ: b.minZ + offset.z, maxZ: b.maxZ + offset.z }));
  }
  for (const [start, end, layer] of [[7, 11, 3], [29, 33, 4]]) {
    const passage = new THREE.Group();
    for (const x of [3.725, 5.275]) box(passage, [0.3, 2.6, end - start], mat.wall, [x, 1.3, (start + end) / 2]);
    for (const y of [-0.15, 2.6]) box(passage, [1.85, 0.3, end - start], mat.wall, [4.5, y, (start + end) / 2]);
    for (const z of [start, end]) {
      for (const x of [3.825, 5.175]) box(passage, [0.08, 2.3, 0.16], mat.metal, [x, 1.15, z]);
      box(passage, [1.43, 0.12, 0.16], mat.metal, [4.5, 2.36, z]);
      if (layer === 4) {
        for (const x of [3.84, 5.16]) box(passage, [0.03, 2.3, 0.18], mat.ink, [x, 1.15, z]);
        box(passage, [1.35, 0.03, 0.18], mat.ink, [4.5, 2.31, z]);
      }
    }
    const light = new THREE.PointLight(colors.plantKey, 12, 6, 2);
    light.position.set(4.5, 2.25, (start + end) / 2);
    light.userData.paletteToken = 'plantKey';
    fixtures.push(light);
    passage.add(light);
    box(passage, [0.65, 0.04, 1.8], mat.fixture, [4.5, 2.42, (start + end) / 2]);
    mergeStatic(passage, resources);
    passage.traverse(object => object.layers.set(layer));
    scene.add(passage);
  }
  cctvCamera.position.x += PLANT_OFFSETS.reactor.x;
  cctvCamera.position.z += PLANT_OFFSETS.reactor.z;

  let latest = null, targets = null, shown = null, clock = 0, currentView = 'reactor';
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
    if (!reduced) clock += dt;
    rodPositions.forEach(([x, z], i) => {
      const fraction = i < 13 ? shown.rods : shown.shutdown;
      place(rods, i, [x, 1.45 + fraction * 1.6, z], [0.055, 1.5, 0.055]);
      place(collars, i, [x, 1.55 + fraction * 1.6, z], [0.17, 0.12, 0.17]);
      const trueFraction = i < 13 ? targets.rods : targets.shutdown;
      for (let n = 0; n < 5; n++) {
        const index = i * 5 + n;
        const lit = trueFraction >= n / 4;
        place(rodLights, index, [x, 1.45 + n * 0.38, z + 0.15], [0.055, 0.055, 0.055]);
        rodLights.setColorAt(index, rodColor.set(colors[lit ? 'lampGlow' : 'lampOff']));
        rodGlow.setX(index, Number(lit));
      }
    });
    rodGlow.needsUpdate = true;
    rodLights.instanceColor.needsUpdate = true;
    levels.forEach(({ at, height }, i) => {
      place(levelFills, i, at, [0.1, Math.max(0.0001, shown.levels[i] * height), 0.04]);
    });
    pumps.forEach((pump, i) => {
      // Pump status switches the lamp. Speed alone drives the coastdown.
      pump.lamp.material = latest.loops[i].pumpRunning ? mat.lit : mat.off;
      if (!reduced) pump.rotor.rotation.y -= targets.pumps[i] * SPIN * dt;
      else pump.rotor.rotation.y = -targets.pumps[i] * Math.PI;
      const angle = pump.rotor.rotation.y;
      const { x, y, z } = pump.rotor.position;
      place(pumpRotors, i, [x, y, z], [0.43, 0.38, 0.43], [0, angle, 0]);
      place(pumpMarks, i, [x + Math.sin(angle) * 0.43, y, z + Math.cos(angle) * 0.43],
        [0.12, 0.4, 0.04], [0, angle, 0]);
      mat.coolant[i].color.copy(cold).lerp(hot, shown.coolant[i]);
    });
    if (!reduced) shaft.rotation.x += targets.shaft * SPIN * dt;
    spray.visible = targets.spray > 0;
    relief.visible = targets.relief > 0;
    vent.visible = targets.vent > 0;
    for (let i = 0; i < spray.count; i++) {
      const fall = (i / spray.count + clock * 0.8) % 1, size = 0.035 + 0.035 * shown.spray;
      place(spray, i, [-5.45 + Math.sin(i * 2.3) * 0.14, 4.5 - fall * 1.1, -0.45], [size, size * 1.8, size]);
    }
    for (const [mesh, x, y, z, amount] of [[relief, -6.5, 6.5, -0.5, shown.relief]]) {
      for (let i = 0; i < mesh.count; i++) {
        const rise = (i / mesh.count + clock * 0.32) % 1, size = (0.14 + rise * 0.4) * amount;
        place(mesh, i, [x + rise * 0.2, y + rise * 1.6, z], [size, size * 1.4, size]);
      }
    }
    vent.children.forEach((sprite, i) => {
      const rise = (i / vent.children.length + clock * 0.32) % 1;
      const size = (0.3 + rise * 0.8) * shown.vent;
      sprite.position.set(HALL_X + 5 + rise * 0.2, 6.7 + rise * 1.6, 0);
      sprite.scale.set(size, size * 1.4, 1);
    });
    gaugeMeshes.forEach(({ local, needles }) => local.forEach((g, i) => {
      const [low, high] = g.pair.range;
      g.fraction = ease(g.fraction, clamp01((g.pair.trueValue - low) / (high - low)), k);
      place(needles, i, [g.at[0], g.at[1] + 0.0303, g.at[2] + 0.09], [1, 1, 1], [0, 0, Math.PI * 0.75 - Math.PI * 1.5 * g.fraction]);
    }));
    return !reduced && (moving || targets.pumps.some(v => v > 0) || targets.shaft > 0 || targets.spray > 0 || targets.relief > 0 || targets.vent > 0);
  }
  function setView(name) {
    const view = VIEWS[name];
    if (!view) throw new Error(`No view named ${name}`);
    currentView = name === 'turbine' ? 'turbine' : 'reactor';
    camera.layers.set(currentView === 'reactor' ? 1 : 2);
    camera.layers.enable(4);
    if (currentView === 'turbine') camera.layers.enable(3);
    camera.position.set(...view.eye);
    camera.lookAt(...view.look);
    camera.rotation.order = 'YXZ';
  }

  setView('reactor');
  return {
    scene, camera, cctvCamera, obstacles, advance: animate, setView,
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
      scene.traverse(object => { if (object.isInstancedMesh) object.dispose(); });
      fixtures.forEach(light => light.dispose()); lighting.dispose();
      scene.environment = null;
      scene.clear();
      resources.disposeAll();
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
