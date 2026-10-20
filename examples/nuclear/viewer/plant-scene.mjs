// The reactor building and the turbine hall, drawn from plant snapshots.
//
// Everything the scene moves comes from instruments(snapshot). Motion eases
// toward each new snapshot. Easing changes how the picture moves, never a
// value: the readings panel and the dials always show the snapshot values as
// they are.
//
// Under prefers-reduced-motion the camera holds still, rotors and particles
// stop, and dials and levels snap to their values.

import * as THREE from '/vendor/three/build/three.module.js';
import { formatGap, formatValue, instruments } from './instruments.mjs';

const TAU = Math.PI * 2;
const HALF_PI = Math.PI / 2;

// Layout, in metres. The reactor building stands left of the turbine hall.
const REACTOR_X = -8;
const HALL_X = 8;
const AXIS_Y = 3;
const SG_X = REACTOR_X + 4.2;
const PZR_X = REACTOR_X - 3.6;
const CORE_BOTTOM = 2.3;
const CORE_HEIGHT = 2;
const LOOP_Z = [-2.4, 2.4]; // steam generator centres, loop A then loop B
const NOZZLE_Z = [-0.6, 0.6]; // where each loop's pipes meet the vessel
const TOWER = { x: HALL_X - 6, z: -12 };
const HEADER_Y = 6.6;

// Motion. Speeds are radians per second at full speed.
const SMOOTH_S = 0.35;
const VIEW_SMOOTH_S = 0.8;
const SPIN = 9;
const STEAM_RATED_KG_S = 800;
const GENERATOR_RATED_MW = 700;
const COOLANT_COLD_C = 290;
const COOLANT_HOT_C = 340;
const STEAM_BEADS = 10;
const PLUME_PUFFS = 4;

export const VIEWS = {
  overview: { eye: [1, 12.5, 40], look: [1, 6.5, 0] },
  reactor: { eye: [REACTOR_X + 0.5, 7.6, 25], look: [REACTOR_X, 3.6, 0] },
  turbine: { eye: [HALL_X + 1, 6.4, 26], look: [HALL_X + 0.5, 3.8, 0] },
};

// Instrument racks stand in front of each building. Each shows six points as
// dial pairs: the reported dial on the left, the true dial on the right.
const RACK_Z = 9.5;
const RACK_W = 6.6;
const RACK_H = 3.5;
const RACK_CY = 2.25;
const RACK_TOP = RACK_CY + RACK_H / 2;
const PX_PER_M = 155;
const RACKS = [
  {
    title: 'Reactor instruments',
    x: REACTOR_X,
    points: [
      ['hot_leg:a', ['Hot leg A']],
      ['hot_leg:b', ['Hot leg B']],
      ['core_exit_temperature', ['Core exit', 'temperature']],
      ['neutron_power', ['Neutron', 'power']],
      ['pressurizer_pressure', ['Pressurizer', 'pressure']],
      ['pressurizer_level', ['Pressurizer', 'level']],
    ],
  },
  {
    title: 'Turbine hall instruments',
    x: HALL_X,
    points: [
      ['steam_pressure', ['Steam', 'pressure']],
      ['steam_generator_level:a', ['Steam gen.', 'level A']],
      ['steam_generator_level:b', ['Steam gen.', 'level B']],
      ['turbine_valve', ['Turbine', 'valve']],
      ['generator_output', ['Generator', 'output']],
      ['condenser_pressure', ['Condenser', 'pressure']],
    ],
  },
];
const DIALS = RACKS.flatMap((rack) =>
  rack.points.map(([key, lines], slot) => ({ rack, key, lines, slot })),
);
const DIAL_COUNT = DIALS.length;

/** The centre of a dial pair, by its rack and its place in the rack (rows of three). */
function dialSlot(rack, slot) {
  const col = slot % 3;
  const row = Math.floor(slot / 3);
  const cx = rack.x + (col - 1) * 1.9;
  const y = RACK_TOP - 0.95 - row * 1.45;
  return { cx, y, reportedX: cx - 0.5, trueX: cx + 0.5 };
}
const DIAL_POSE = DIALS.map(({ rack, slot }) => dialSlot(rack, slot));

const TOKEN = {
  lightKey: '--light-key',
  surface: '--surface',
  raised: '--surface-raised',
  sunken: '--surface-sunken',
  ink: '--ink',
  steel: '--steel',
  metal: '--metal',
  line: '--line-strong',
  steam: '--steam',
  accent: '--accent',
  warning: '--warning',
  coldCoolant: '--coolant-cold',
  hotCoolant: '--coolant-hot',
};

const clamp01 = (v) => Math.min(1, Math.max(0, v));

function readColors(el) {
  const style = getComputedStyle(el);
  const out = {};
  for (const [name, token] of Object.entries(TOKEN)) {
    out[name] = style.getPropertyValue(token).trim();
  }
  return out;
}

/** What the scene moves toward, read from one snapshot's instruments. */
function targetsFrom(r) {
  const turbineOpen = r.secondary.turbineTripped ? 0 : clamp01(r.secondary.turbineValvePercent / 100);
  const steamKg = r.loops[0].steamKgS + r.loops[1].steamKgS;
  const condenserRise = clamp01((r.secondary.condenserPressureKpa - 5) / 10);
  return {
    rods: clamp01(r.reactor.controlRodWithdrawnPercent / 100),
    shutdown: clamp01(r.reactor.shutdownRodInsertedPercent / 100),
    core: 0.12 + 0.5 * clamp01(r.reactor.neutronPowerPercent / 100),
    sgLevel: r.loops.map((l) => clamp01(l.steamGeneratorLevelPercent / 100)),
    pzrLevel: clamp01(r.pressurizer.levelPercent / 100),
    spray: clamp01(r.pressurizer.sprayPercent / 100),
    relief: r.pressurizer.reliefOpen ? 1 : 0,
    heater: r.pressurizer.heatersOn ? 1 : 0,
    pumpSpeed: r.loops.map((l) => (l.pumpRunning ? clamp01(l.pumpSpeedPercent / 100) * SPIN : 0)),
    turbineSpeed: turbineOpen * SPIN,
    generatorSpeed: clamp01(r.secondary.generatorMw / GENERATOR_RATED_MW) * SPIN,
    steamFlow: turbineOpen * clamp01(steamKg / STEAM_RATED_KG_S),
    // With cooling lost the plume starts larger, then grows as the condenser warms.
    plume: r.secondary.circulatingWaterRunning ? 0.15 + 0.5 * condenserRise : 0.6 + 0.4 * condenserRise,
    coolant: r.loops.map((l) => clamp01((l.hotLegC - COOLANT_COLD_C) / (COOLANT_HOT_C - COOLANT_COLD_C))),
  };
}

const START_TARGETS = {
  rods: 0.5,
  shutdown: 0,
  core: 0.2,
  sgLevel: [0.5, 0.5],
  pzrLevel: 0.5,
  spray: 0,
  relief: 0,
  heater: 0,
  pumpSpeed: [0, 0],
  turbineSpeed: 0,
  generatorSpeed: 0,
  steamFlow: 0,
  plume: 0.15,
  coolant: [0, 0],
};

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
function mergeStatic(root, track) {
  root.updateMatrixWorld(true);
  const byMaterial = new Map();
  const found = [];
  root.traverse((object) => {
    if (!(object instanceof THREE.Mesh) || object instanceof THREE.InstancedMesh) return;
    if (isAnimated(object, root)) return;
    found.push(object);
    const list = byMaterial.get(object.material) ?? [];
    list.push({ geometry: object.geometry, matrix: object.matrixWorld.clone() });
    byMaterial.set(object.material, list);
  });
  for (const mesh of found) mesh.removeFromParent();
  for (const [material, list] of byMaterial) {
    root.add(new THREE.Mesh(joinGeometries(list, track), material));
  }
}

/** A pipe along a polyline, with a round joint at each bend. */
function pipe(parent, points, radius, material, track) {
  const up = new THREE.Vector3(0, 1, 0);
  for (let i = 0; i < points.length - 1; i++) {
    const a = new THREE.Vector3(...points[i]);
    const b = new THREE.Vector3(...points[i + 1]);
    const dir = b.clone().sub(a);
    const length = dir.length();
    const mesh = new THREE.Mesh(track.add(new THREE.CylinderGeometry(radius, radius, length, 6)), material);
    mesh.position.copy(a).add(b).multiplyScalar(0.5);
    mesh.quaternion.setFromUnitVectors(up, dir.normalize());
    parent.add(mesh);
  }
  const joint = track.add(new THREE.SphereGeometry(radius, 6, 4));
  for (const p of points.slice(1, -1)) {
    const mesh = new THREE.Mesh(joint, material);
    mesh.position.set(...p);
    parent.add(mesh);
  }
}

function cylinder(parent, radius, height, material, at, axis, track) {
  const mesh = new THREE.Mesh(track.add(new THREE.CylinderGeometry(radius, radius, height, 10)), material);
  mesh.position.set(...at);
  if (axis === 'x') mesh.rotation.z = HALF_PI;
  parent.add(mesh);
  return mesh;
}

function box(parent, size, material, at, track) {
  const mesh = new THREE.Mesh(track.add(new THREE.BoxGeometry(...size)), material);
  mesh.position.set(...at);
  parent.add(mesh);
  return mesh;
}

/** The top or bottom half of a sphere, for a vessel end. */
function cap(parent, radius, material, at, top, track) {
  const thetaStart = top ? 0 : HALF_PI;
  const geometry = track.add(new THREE.SphereGeometry(radius, 8, 4, 0, TAU, thetaStart, HALF_PI));
  const mesh = new THREE.Mesh(geometry, material);
  mesh.position.set(...at);
  parent.add(mesh);
  return mesh;
}

/**
 * A rotor drawn as a drum with four stripes along it, so its spin shows. The
 * returned group rotates about its own x axis.
 */
function spinner(parent, at, radius, length, bodyMaterial, stripeMaterial, track) {
  const group = new THREE.Group();
  group.position.set(...at);
  group.userData.animated = true;
  parent.add(group);
  const body = new THREE.Mesh(track.add(new THREE.CylinderGeometry(radius, radius, length, 8)), bodyMaterial);
  body.rotation.z = HALF_PI;
  group.add(body);
  const stripe = track.add(new THREE.BoxGeometry(length * 0.98, 0.1, 0.1));
  const stripes = [];
  for (let k = 0; k < 4; k++) {
    const angle = (k * TAU) / 4;
    const matrix = new THREE.Matrix4().makeTranslation(0, Math.cos(angle) * (radius + 0.03), Math.sin(angle) * (radius + 0.03));
    stripes.push({ geometry: stripe, matrix });
  }
  group.add(new THREE.Mesh(joinGeometries(stripes, track), stripeMaterial));
  return group;
}

// One shared helper object, used to write instance matrices.
const dummy = new THREE.Object3D();

/** Places instance k of an instanced mesh. A zero scale hides it. */
function place(mesh, k, { x = 0, y = 0, z = 0, rz = 0, sx = 1, sy = 1, sz = 1 }) {
  dummy.position.set(x, y, z);
  dummy.rotation.set(0, 0, rz);
  dummy.scale.set(sx, sy, sz);
  dummy.updateMatrix();
  mesh.setMatrixAt(k, dummy.matrix);
}

/** Needle angle for a fraction of a dial's scale: lower left at 0, lower right at 1. */
const needleAngle = (fraction) => (3 * Math.PI) / 4 - ((3 * Math.PI) / 2) * fraction;

const FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif";

/** Prints one rack's title and the labels under its dials onto its face. */
function paintRack(canvas, rack, colors) {
  const ctx = canvas.getContext('2d');
  const px = (metres) => metres * PX_PER_M;
  const left = rack.x - RACK_W / 2;
  ctx.fillStyle = colors.steel;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = colors.ink;
  ctx.textBaseline = 'top';
  ctx.font = `600 ${px(0.25)}px ${FONT}`;
  ctx.textAlign = 'left';
  ctx.fillText(rack.title, px(0.3), px(0.16));
  ctx.font = `${px(0.18)}px ${FONT}`;
  ctx.textAlign = 'center';
  rack.points.forEach(([, lines], slot) => {
    const pose = dialSlot(rack, slot);
    lines.forEach((line, i) => {
      // Labels sit under the dial pair, one line per row of text.
      const worldY = pose.y - 0.5 - i * 0.24;
      ctx.fillText(line, px(pose.cx - left), px(RACK_TOP - worldY));
    });
  });
}

/**
 * The 3D scene. `container` is the element the canvas fills; give it a size.
 * Returns update(snapshot), setView(name) and dispose().
 */
export function createPlantScene(container) {
  const resources = tracker();
  const colors = readColors(container);
  const reducedQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');

  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.domElement.setAttribute('role', 'img');
  renderer.domElement.setAttribute(
    'aria-label',
    'Three-dimensional view of the reactor building and turbine hall. The readings panel lists the same values.',
  );
  container.append(renderer.domElement);
  container.dataset.plantState = 'waiting';

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 200);
  const fill = new THREE.HemisphereLight();
  scene.add(fill);
  const sun = new THREE.DirectionalLight();
  sun.intensity = 1.5;
  sun.position.set(-6, 14, 18);
  scene.add(sun);

  // One material per role. applyColors() sets the colors from the page's tokens.
  const mat = {
    shell: resources.add(new THREE.MeshLambertMaterial({ transparent: true, opacity: 0.22, depthWrite: false })),
    containment: resources.add(new THREE.MeshLambertMaterial({ transparent: true, opacity: 0.1, depthWrite: false })),
    metal: resources.add(new THREE.MeshLambertMaterial()),
    concrete: resources.add(new THREE.MeshLambertMaterial()),
    ink: resources.add(new THREE.MeshLambertMaterial()),
    water: resources.add(new THREE.MeshLambertMaterial({ transparent: true, opacity: 0.32, depthWrite: false })),
    steam: resources.add(new THREE.MeshLambertMaterial({ transparent: true, opacity: 0.5, depthWrite: false })),
    steamBead: resources.add(new THREE.MeshLambertMaterial({ transparent: true, opacity: 0.85, depthWrite: false })),
    face: resources.add(new THREE.MeshLambertMaterial()),
    core: resources.add(new THREE.MeshLambertMaterial({ transparent: true, opacity: 0.2, depthWrite: false })),
    accent: resources.add(new THREE.MeshBasicMaterial()),
    warning: resources.add(new THREE.MeshBasicMaterial()),
    coolant: [resources.add(new THREE.MeshLambertMaterial()), resources.add(new THREE.MeshLambertMaterial())],
  };
  const coldCoolant = new THREE.Color(colors.coldCoolant);
  const hotCoolant = new THREE.Color(colors.hotCoolant);
  const shownCoolant = [coldCoolant.clone(), coldCoolant.clone()];
  const coolantTarget = new THREE.Color();

  // Each rack face is its own canvas: its title and dial labels are printed on it.
  const rackFaces = RACKS.map((rack) => {
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(RACK_W * PX_PER_M);
    canvas.height = Math.round(RACK_H * PX_PER_M);
    const texture = resources.add(new THREE.CanvasTexture(canvas));
    texture.colorSpace = THREE.SRGBColorSpace;
    const material = resources.add(new THREE.MeshBasicMaterial({ map: texture }));
    return { rack, canvas, texture, material };
  });

  function applyColors() {
    fill.color.set(colors.lightKey);
    fill.groundColor.set(colors.lightKey);
    sun.color.set(colors.lightKey);
    mat.shell.color.set(colors.raised);
    mat.containment.color.set(colors.line);
    mat.metal.color.set(colors.metal);
    mat.concrete.color.set(colors.line);
    mat.ink.color.set(colors.ink);
    mat.water.color.set(colors.ink);
    mat.steam.color.set(colors.steam);
    mat.steamBead.color.set(colors.steam);
    mat.face.color.set(colors.raised);
    mat.core.color.set(colors.accent);
    mat.accent.color.set(colors.accent);
    mat.warning.color.set(colors.warning);
    coldCoolant.set(colors.coldCoolant);
    hotCoolant.set(colors.hotCoolant);
    scene.background = new THREE.Color(colors.sunken);
    for (const face of rackFaces) {
      paintRack(face.canvas, face.rack, colors);
      face.texture.needsUpdate = true;
    }
  }
  applyColors();

  const plant = new THREE.Group();
  scene.add(plant);

  // --- Reactor building ----------------------------------------------------
  cylinder(plant, 5.4, 11, mat.containment, [REACTOR_X, 5.5, 0], 'y', resources);
  cap(plant, 5.4, mat.containment, [REACTOR_X, 11, 0], true, resources);
  box(plant, [12.4, 0.4, 12.4], mat.concrete, [REACTOR_X, 0.2, 0], resources);

  cylinder(plant, 1.2, 2.6, mat.metal, [REACTOR_X, 3.3, 0], 'y', resources);
  cap(plant, 1.2, mat.metal, [REACTOR_X, 4.6, 0], true, resources);
  cap(plant, 1.2, mat.metal, [REACTOR_X, 2.0, 0], false, resources);
  const core = cylinder(plant, 0.8, CORE_HEIGHT, mat.core, [REACTOR_X, CORE_BOTTOM + CORE_HEIGHT / 2, 0], 'y', resources);

  // Rods are unit cylinders scaled to the core height.
  const rodGeometry = resources.add(new THREE.CylinderGeometry(0.05, 0.05, 1, 5));
  const controlRods = new THREE.InstancedMesh(rodGeometry, mat.ink, 12);
  const shutdownRods = new THREE.InstancedMesh(rodGeometry, mat.ink, 8);
  plant.add(controlRods, shutdownRods);

  // Steam generators are glass, so the water level shows through the shell.
  const levelGeometry = resources.add(new THREE.CylinderGeometry(0.9, 0.9, 1, 12));
  levelGeometry.translate(0, 0.5, 0);
  const sgLevels = LOOP_Z.map((z) => {
    cylinder(plant, 0.95, 4.6, mat.shell, [SG_X, 3.2, z], 'y', resources);
    cap(plant, 0.95, mat.shell, [SG_X, 5.5, z], true, resources);
    cap(plant, 0.95, mat.shell, [SG_X, 0.9, z], false, resources);
    const level = new THREE.Mesh(levelGeometry, mat.water);
    level.userData.animated = true;
    level.position.set(SG_X, 0.95, z);
    plant.add(level);
    return level;
  });

  // Pressurizer, with its water level, heater, spray and relief.
  cylinder(plant, 0.6, 4.6, mat.shell, [PZR_X, 3.3, 0], 'y', resources);
  cap(plant, 0.6, mat.shell, [PZR_X, 5.6, 0], true, resources);
  cap(plant, 0.6, mat.shell, [PZR_X, 1.0, 0], false, resources);
  const pzrGeometry = resources.add(new THREE.CylinderGeometry(0.55, 0.55, 1, 10));
  pzrGeometry.translate(0, 0.5, 0);
  const pzrLevel = new THREE.Mesh(pzrGeometry, mat.water);
  pzrLevel.userData.animated = true;
  pzrLevel.position.set(PZR_X, 1.05, 0);
  plant.add(pzrLevel);
  const heater = cylinder(plant, 0.35, 0.8, mat.accent, [PZR_X, 1.5, 0], 'y', resources);
  heater.userData.animated = true;
  const spray = new THREE.InstancedMesh(resources.add(new THREE.SphereGeometry(0.07, 4, 3)), mat.water, 10);
  const reliefPuffs = new THREE.InstancedMesh(resources.add(new THREE.SphereGeometry(0.35, 6, 4)), mat.steam, 5);
  plant.add(spray, reliefPuffs);

  // Pipes: both coolant loops, the surge line and the relief line.
  for (let i = 0; i < 2; i++) {
    const zs = LOOP_Z[i];
    const zn = NOZZLE_Z[i];
    pipe(
      plant,
      [[REACTOR_X + 0.6, 3.9, zn], [REACTOR_X + 2.2, 3.9, zn], [REACTOR_X + 2.2, 3.9, zs], [SG_X - 0.95, 3.9, zs]],
      0.28,
      mat.coolant[i],
      resources,
    );
    pipe(
      plant,
      [[SG_X - 0.95, 1.5, zs], [REACTOR_X + 1.9, 1.5, zs], [REACTOR_X + 1.9, 1.5, zn], [REACTOR_X + 0.6, 1.5, zn]],
      0.28,
      mat.coolant[i],
      resources,
    );
  }
  pipe(plant, [[PZR_X, 1.0, 0], [PZR_X + 1.2, 1.0, 0], [PZR_X + 1.2, 2.8, 0], [REACTOR_X - 0.6, 2.8, 0]], 0.2, mat.metal, resources);
  pipe(plant, [[PZR_X, 5.6, 0], [PZR_X, 6.9, 0]], 0.14, mat.metal, resources);

  // Coolant pumps: a housing with spinning stripes, and a status lamp above.
  const pumps = LOOP_Z.map((z) => {
    const at = [REACTOR_X + 2.6, 1.5, z];
    const rotor = spinner(plant, at, 0.42, 1.1, mat.metal, mat.ink, resources);
    const lamp = new THREE.Mesh(resources.add(new THREE.SphereGeometry(0.1, 6, 4)), mat.ink);
    lamp.userData.animated = true;
    lamp.position.set(at[0], at[1] + 0.7, at[2]);
    plant.add(lamp);
    return { rotor, lamp };
  });

  // Steam from both generators joins one header that runs to the turbine.
  const headerPoints = [
    [SG_X, HEADER_Y, 0],
    [HALL_X - 3.2, HEADER_Y, 0],
    [HALL_X - 3.2, AXIS_Y + 0.9, 0],
  ];
  for (const z of LOOP_Z) {
    pipe(plant, [[SG_X, 6.2, z], [SG_X, HEADER_Y, z], [SG_X, HEADER_Y, 0]], 0.3, mat.metal, resources);
  }
  pipe(plant, headerPoints, 0.36, mat.metal, resources);
  const header = new THREE.CurvePath();
  header.add(new THREE.LineCurve3(new THREE.Vector3(...headerPoints[0]), new THREE.Vector3(...headerPoints[1])));
  header.add(new THREE.LineCurve3(new THREE.Vector3(...headerPoints[1]), new THREE.Vector3(...headerPoints[2])));
  const steamBeads = new THREE.InstancedMesh(
    resources.add(new THREE.SphereGeometry(0.17, 6, 4)),
    mat.steamBead,
    STEAM_BEADS,
  );
  plant.add(steamBeads);

  // --- Turbine hall --------------------------------------------------------
  const hall = new THREE.Group();
  plant.add(hall);
  box(hall, [16, 0.4, 12], mat.concrete, [HALL_X, 0.2, 0], resources);
  box(hall, [12, 1.8, 3.2], mat.concrete, [HALL_X + 1.5, 0.9, 0], resources);
  for (const x of [-7.6, 7.6]) {
    for (const z of [-5.6, 5.6]) box(hall, [0.5, 8.4, 0.5], mat.metal, [HALL_X + x, 4.2, z], resources);
    box(hall, [0.35, 0.45, 12], mat.metal, [HALL_X + x, 8.8, 0], resources);
  }
  box(hall, [16, 0.4, 0.4], mat.metal, [HALL_X, 8.8, -5.6], resources);
  box(hall, [16, 0.4, 0.4], mat.metal, [HALL_X, 8.8, 5.6], resources);

  // Turbine casings are glass, so the rotors show; the last casing is the generator.
  const casings = [
    { x: -3.2, r: 0.8, len: 2.2 },
    { x: -0.4, r: 1.15, len: 2.6 },
    { x: 2.4, r: 1.15, len: 2.6 },
    { x: 5.6, r: 1.0, len: 2.8 },
  ];
  const rotors = casings.map((c) => {
    cylinder(hall, c.r, c.len, mat.shell, [HALL_X + c.x, AXIS_Y, 0], 'x', resources);
    return spinner(hall, [HALL_X + c.x, AXIS_Y, 0], c.r * 0.7, c.len, mat.metal, mat.ink, resources);
  });
  const turbineRotors = rotors.slice(0, 3);
  const generatorRotor = rotors[3];

  // Condenser, its neck from the low-pressure casing, and the water pipes to the tower.
  box(hall, [6, 1.5, 2.9], mat.metal, [HALL_X - 0.4, 0.85, -4.1], resources);
  pipe(hall, [[HALL_X - 0.4, 1.85, 0], [HALL_X - 0.4, 1.85, -1.3], [HALL_X - 0.4, 1.55, -2.7]], 0.45, mat.metal, resources);
  pipe(hall, [[HALL_X - 2, 0.6, -5.6], [HALL_X - 2, 0.6, -10.4], [TOWER.x + 2.2, 0.6, TOWER.z]], 0.4, mat.metal, resources);
  pipe(hall, [[HALL_X + 1, 0.6, -5.6], [HALL_X + 1, 0.6, -10.4], [TOWER.x + 2.2, 0.6, TOWER.z + 0.6]], 0.4, mat.metal, resources);
  const towerProfile = [
    new THREE.Vector2(2.8, 0),
    new THREE.Vector2(2.5, 1.5),
    new THREE.Vector2(1.9, 5),
    new THREE.Vector2(2.2, 7.2),
    new THREE.Vector2(2.5, 8.6),
  ];
  const tower = new THREE.Mesh(resources.add(new THREE.LatheGeometry(towerProfile, 12)), mat.concrete);
  tower.position.set(TOWER.x, 0, TOWER.z);
  plant.add(tower);
  const plumePuffs = new THREE.InstancedMesh(resources.add(new THREE.SphereGeometry(0.7, 6, 4)), mat.steam, PLUME_PUFFS);
  plant.add(plumePuffs);

  // --- Instrument racks ----------------------------------------------------
  for (const face of rackFaces) {
    const { rack } = face;
    box(plant, [RACK_W + 0.2, RACK_H + 0.2, 0.3], mat.metal, [rack.x, RACK_CY, RACK_Z - 0.15], resources);
    const panel = new THREE.Mesh(resources.add(new THREE.PlaneGeometry(RACK_W, RACK_H)), face.material);
    panel.position.set(rack.x, RACK_CY, RACK_Z + 0.151);
    plant.add(panel);
  }

  const dialFace = resources.add(new THREE.CircleGeometry(0.26, 14));
  const needleGeometry = resources.add(new THREE.BoxGeometry(0.05, 0.2, 0.02));
  needleGeometry.translate(0, 0.1, 0);
  const ringGeometry = resources.add(new THREE.RingGeometry(0.285, 0.315, 10));
  const alarmRingGeometry = resources.add(new THREE.RingGeometry(0.36, 0.4, 10));
  const linkGeometry = resources.add(new THREE.BoxGeometry(1, 0.04, 0.02));
  const reportedFaces = new THREE.InstancedMesh(dialFace, mat.face, DIAL_COUNT);
  const trueFaces = new THREE.InstancedMesh(dialFace, mat.face, DIAL_COUNT);
  const reportedNeedles = new THREE.InstancedMesh(needleGeometry, mat.ink, DIAL_COUNT);
  const trueNeedles = new THREE.InstancedMesh(needleGeometry, mat.accent, DIAL_COUNT);
  const trueRings = new THREE.InstancedMesh(ringGeometry, mat.accent, DIAL_COUNT);
  const frozenRings = new THREE.InstancedMesh(ringGeometry, mat.ink, DIAL_COUNT);
  const divergedRings = new THREE.InstancedMesh(alarmRingGeometry, mat.warning, DIAL_COUNT);
  const divergedLinks = new THREE.InstancedMesh(linkGeometry, mat.warning, DIAL_COUNT);
  const dialMeshes = [reportedFaces, trueFaces, reportedNeedles, trueNeedles, trueRings, frozenRings, divergedRings, divergedLinks];
  plant.add(...dialMeshes);
  DIAL_POSE.forEach((s, k) => {
    place(reportedFaces, k, { x: s.reportedX, y: s.y, z: RACK_Z + 0.17 });
    place(trueFaces, k, { x: s.trueX, y: s.y, z: RACK_Z + 0.17 });
    place(trueRings, k, { x: s.trueX, y: s.y, z: RACK_Z + 0.18 });
  });
  for (const m of [reportedFaces, trueFaces, trueRings]) m.instanceMatrix.needsUpdate = true;

  // Static parts are joined by material; the moving parts above stay separate.
  mergeStatic(plant, resources);

  // --- Animation state -----------------------------------------------------
  // `targets` is what the scene moves toward; `shown` is where it is now.
  let targets = START_TARGETS;
  let latest = null;
  const shown = structuredClone(START_TARGETS);
  const dialFraction = DIALS.map(() => ({ reported: 0, true: 0 }));
  let currentView = 'overview';
  const viewEye = new THREE.Vector3(...VIEWS.overview.eye);
  const viewLook = new THREE.Vector3(...VIEWS.overview.look);
  const eyeGoal = new THREE.Vector3();
  const lookGoal = new THREE.Vector3();
  let clock = 0;
  const spinAngle = { pump: [0, 0], turbine: 0, generator: 0 };

  let width = 1;
  let height = 1;
  let visible = true;
  let disposed = false;
  let last = performance.now();
  let raf = 0;

  function resize() {
    width = Math.max(1, container.clientWidth);
    height = Math.max(1, container.clientHeight);
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
  }

  function ease(value, target, k) {
    return value + (target - value) * k;
  }

  function animate(dt) {
    const reduced = reducedQuery.matches;
    const k = reduced ? 1 : 1 - Math.exp(-dt / SMOOTH_S);
    const kView = reduced ? 1 : 1 - Math.exp(-dt / VIEW_SMOOTH_S);
    if (!reduced) clock += dt;

    shown.rods = ease(shown.rods, targets.rods, k);
    shown.shutdown = ease(shown.shutdown, targets.shutdown, k);
    shown.core = ease(shown.core, targets.core, k);
    shown.pzrLevel = ease(shown.pzrLevel, targets.pzrLevel, k);
    shown.spray = ease(shown.spray, targets.spray, k);
    shown.relief = ease(shown.relief, targets.relief, k);
    shown.heater = ease(shown.heater, targets.heater, k);
    shown.turbineSpeed = ease(shown.turbineSpeed, targets.turbineSpeed, k);
    shown.generatorSpeed = ease(shown.generatorSpeed, targets.generatorSpeed, k);
    shown.steamFlow = ease(shown.steamFlow, targets.steamFlow, k);
    shown.plume = ease(shown.plume, targets.plume, k);
    for (let i = 0; i < 2; i++) {
      shown.sgLevel[i] = ease(shown.sgLevel[i], targets.sgLevel[i], k);
      shown.pumpSpeed[i] = ease(shown.pumpSpeed[i], targets.pumpSpeed[i], k);
      coolantTarget.copy(coldCoolant).lerp(hotCoolant, targets.coolant[i]);
      shownCoolant[i].lerp(coolantTarget, k);
      mat.coolant[i].color.copy(shownCoolant[i]);
    }
    mat.core.opacity = shown.core;

    // Control rods withdraw with the rod position; shutdown rods insert.
    for (let i = 0; i < 12; i++) {
      const angle = (i / 12) * TAU;
      const tip = CORE_BOTTOM + shown.rods * CORE_HEIGHT;
      place(controlRods, i, {
        x: REACTOR_X + 0.55 * Math.cos(angle),
        y: tip + CORE_HEIGHT / 2,
        z: 0.55 * Math.sin(angle),
        sy: CORE_HEIGHT,
      });
    }
    for (let i = 0; i < 8; i++) {
      const angle = (i / 8) * TAU + Math.PI / 8;
      const tip = CORE_BOTTOM + (1 - shown.shutdown) * CORE_HEIGHT;
      place(shutdownRods, i, {
        x: REACTOR_X + 0.3 * Math.cos(angle),
        y: tip + CORE_HEIGHT / 2,
        z: 0.3 * Math.sin(angle),
        sy: CORE_HEIGHT,
      });
    }
    controlRods.instanceMatrix.needsUpdate = true;
    shutdownRods.instanceMatrix.needsUpdate = true;

    // Water levels: the fill height follows the level.
    for (let i = 0; i < 2; i++) sgLevels[i].scale.y = Math.max(0.001, shown.sgLevel[i] * 4.4);
    pzrLevel.scale.y = Math.max(0.001, shown.pzrLevel * 4.4);
    heater.visible = shown.heater > 0.5;

    // Spray falls through the pressurizer while spray is open.
    const sprayScale = shown.spray > 0.03 ? 1 : 0;
    for (let i = 0; i < 10; i++) {
      const fall = (i / 10 + (reduced ? 0 : clock * 0.9)) % 1;
      place(spray, i, {
        x: PZR_X + 0.15 * Math.sin(i * 2.3),
        y: 5.3 - fall * 3.9,
        z: 0.1 * Math.cos(i * 1.7),
        sx: sprayScale,
        sy: sprayScale,
        sz: sprayScale,
      });
    }
    spray.instanceMatrix.needsUpdate = true;

    // Relief puffs rise from the relief line while the valve is open.
    for (let i = 0; i < 5; i++) {
      const rise = (i / 5 + (reduced ? 0 : clock * 0.4)) % 1;
      const size = shown.relief > 0.5 ? 0.6 + 0.9 * rise : 0;
      place(reliefPuffs, i, { x: PZR_X, y: 7 + rise * 2.8, z: 0, sx: size, sy: size, sz: size });
    }
    reliefPuffs.instanceMatrix.needsUpdate = true;

    // Pumps, turbine and generator spin at their speeds. Reduced motion holds them still.
    if (!reduced) {
      for (let i = 0; i < 2; i++) {
        spinAngle.pump[i] += shown.pumpSpeed[i] * dt;
        pumps[i].rotor.rotation.x = spinAngle.pump[i];
      }
      spinAngle.turbine += shown.turbineSpeed * dt;
      spinAngle.generator += shown.generatorSpeed * dt;
      for (const rotor of turbineRotors) rotor.rotation.x = spinAngle.turbine;
      generatorRotor.rotation.x = spinAngle.generator;
    }
    for (let i = 0; i < 2; i++) {
      const running = latest ? latest.loops[i].pumpRunning : false;
      pumps[i].lamp.material = running ? mat.accent : mat.ink;
    }

    // Steam beads run along the header while steam goes to the turbine.
    const beadScale = shown.steamFlow > 0.02 ? 1 : 0;
    for (let i = 0; i < STEAM_BEADS; i++) {
      const u = (i / STEAM_BEADS + (reduced ? 0 : clock * shown.steamFlow * 0.25)) % 1;
      const p = header.getPointAt(u);
      place(steamBeads, i, { x: p.x, y: p.y, z: p.z, sx: beadScale, sy: beadScale, sz: beadScale });
    }
    steamBeads.instanceMatrix.needsUpdate = true;

    // The plume at the cooling tower grows with the plume level, and is absent when there is none.
    const plumeOn = shown.plume > 0.05;
    for (let i = 0; i < PLUME_PUFFS; i++) {
      const rise = (i / PLUME_PUFFS + (reduced ? 0 : clock * 0.2)) % 1;
      const size = plumeOn ? (0.9 + 1.8 * shown.plume) * (0.6 + 1.2 * rise) : 0;
      place(plumePuffs, i, { x: TOWER.x, y: 8.8 + rise * 5, z: TOWER.z, sx: size, sy: size, sz: size });
    }
    plumePuffs.instanceMatrix.needsUpdate = true;

    // Dials ease to the reported and the true values; the rings and link follow the flags.
    DIALS.forEach((d, idx) => {
      const pair = latest ? latest.pairs.find((p) => p.key === d.key) : null;
      const range = pair ? pair.range : [0, 1];
      const fraction = (value) => clamp01((value - range[0]) / (range[1] - range[0]));
      const f = dialFraction[idx];
      f.reported = ease(f.reported, pair && pair.reported !== null ? fraction(pair.reported) : 0, k);
      f.true = ease(f.true, pair ? fraction(pair.trueValue) : 0, k);
      const s = DIAL_POSE[idx];
      place(reportedNeedles, idx, { x: s.reportedX, y: s.y, z: RACK_Z + 0.2, rz: needleAngle(f.reported) });
      place(trueNeedles, idx, { x: s.trueX, y: s.y, z: RACK_Z + 0.2, rz: needleAngle(f.true) });
      const frozen = pair ? pair.frozen : false;
      const marked = pair ? pair.marked : false;
      const on = (flag) => (flag ? 1 : 0);
      place(frozenRings, idx, { x: s.reportedX, y: s.y, z: RACK_Z + 0.18, sx: on(frozen), sy: on(frozen) });
      place(divergedRings, idx, { x: s.reportedX, y: s.y, z: RACK_Z + 0.18, sx: on(marked), sy: on(marked) });
      place(divergedLinks, idx, {
        x: (s.reportedX + s.trueX) / 2,
        y: s.y,
        z: RACK_Z + 0.16,
        sx: marked ? s.trueX - s.reportedX : 0,
        sy: on(marked),
      });
    });
    for (const m of [reportedNeedles, trueNeedles, frozenRings, divergedRings, divergedLinks]) {
      m.instanceMatrix.needsUpdate = true;
    }

    // The camera eases to its view, or jumps when motion is reduced.
    const view = VIEWS[currentView];
    eyeGoal.set(...view.eye);
    lookGoal.set(...view.look);
    viewEye.lerp(eyeGoal, kView);
    viewLook.lerp(lookGoal, kView);
    camera.position.copy(viewEye);
    camera.lookAt(viewLook);

    renderer.render(scene, camera);
  }

  function frame(now) {
    if (disposed) return;
    raf = requestAnimationFrame(frame);
    const dt = Math.min(0.1, (now - last) / 1000);
    last = now;
    if (visible) animate(dt);
  }

  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(container);
  const visibilityObserver = new IntersectionObserver((entries) => {
    visible = entries.some((entry) => entry.isIntersecting);
  });
  visibilityObserver.observe(container);

  const onTheme = () => {
    Object.assign(colors, readColors(container));
    applyColors();
  };
  darkQuery.addEventListener('change', onTheme);
  const themeObserver = new MutationObserver(onTheme);
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  resize();
  raf = requestAnimationFrame(frame);

  return {
    /** Shows one plant snapshot. The values are read now; the motion eases toward them. */
    update(snapshot) {
      latest = instruments(snapshot);
      targets = targetsFrom(latest);
      container.dataset.plantState = 'live';
      return latest;
    },
    /** Moves the camera to a named view: overview, reactor or turbine. */
    setView(name) {
      if (!(name in VIEWS)) throw new Error(`no view named ${name}`);
      currentView = name;
    },
    dispose() {
      disposed = true;
      cancelAnimationFrame(raf);
      resizeObserver.disconnect();
      visibilityObserver.disconnect();
      themeObserver.disconnect();
      darkQuery.removeEventListener('change', onTheme);
      renderer.dispose();
      resources.disposeAll();
      renderer.domElement.remove();
      delete container.dataset.plantState;
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

  const alarmsHeading = document.createElement('h3');
  alarmsHeading.textContent = 'Alarms';
  const alarmList = document.createElement('ul');
  const faultsHeading = document.createElement('h3');
  faultsHeading.textContent = 'Equipment and trips';
  const faultList = document.createElement('ul');

  section.append(heading, status, legend, table, alarmsHeading, alarmList, faultsHeading, faultList);
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
      alarmList.replaceChildren(
        ...(r.alarms.length === 0
          ? [textItem('No alarms lit.')]
          : r.alarms.map((a) => textItem(`${a.label} (${a.state})`))),
      );
      faultList.replaceChildren(
        textItem(r.reactor.tripped ? `Reactor tripped: ${r.reactor.tripCause}.` : 'Reactor not tripped.'),
        ...(r.processFaults.length === 0
          ? [textItem('No equipment faults.')]
          : r.processFaults.map((f) => textItem(`${f.label}.`))),
      );
      return r;
    },
    dispose() {
      section.remove();
    },
  };
}

function textItem(text) {
  const li = document.createElement('li');
  li.textContent = text;
  return li;
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
