// One stage owns the renderer, the room camera, and the live containment feed.
import * as THREE from '/vendor/three/build/three.module.js';
import { KNOBS } from './control-room.mjs';
import { formatValue } from './instruments.mjs';
import { createMeters, paintLetters } from './meters.mjs';
import { ROOM, FLOOR, CEILING_LIGHTS, DEFAULT_VIEW, BOARD, BOARDS, BOARD_PX, DESKS, CHAIRS, CCTV, DOOR, DOORWAYS, COLLISIONS, STANDING_SPOTS,
  boardPoint, boardLayout, windowState, devicePlacements, fitSpot, deskOutline, mimicLines } from './board-layout.mjs';
import { look, walk, walkDelta, walkPath, glidePose, doorwayCrossing, doorwayFade } from './room-motion.mjs';
import { createPlantScene, mergeStatic, VIEWS } from './plant-scene.mjs';
import { createRenderer, createEnvironment, createLighting, createMaterial, applyMaterialPalette,
  setIndicator, bakeRoomGeometry, roomLightAt } from './look.mjs';

const FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif";

export function createControlBoard(container, { knobIds, knobLabels, knobKinds, onDevice, theme, reducedMotion }) {
  const resources = new Set();
  const track = resource => { resources.add(resource); return resource; };
  const listeners = [];
  const listen = (target, event, fn) => {
    target.addEventListener(event, fn);
    listeners.push(() => target.removeEventListener(event, fn));
  };
  const renderer = createRenderer(THREE);
  let pixelRatio = Math.min(window.devicePixelRatio || 1, 1.5);
  renderer.setPixelRatio(pixelRatio);
  const canvas = renderer.domElement;
  canvas.setAttribute('role', 'img');
  canvas.tabIndex = 0;
  canvas.setAttribute('aria-describedby', 'cr-walk-help');
  container.append(canvas);
  const scene = new THREE.Scene();
  const environment = track(createEnvironment(THREE, renderer, theme));
  scene.environment = environment.texture;
  const camera = new THREE.PerspectiveCamera(STANDING_SPOTS[DEFAULT_VIEW].fov, 1, 0.05, 100);
  camera.rotation.order = 'YXZ';
  const lighting = createLighting(THREE, scene, theme);
  const material = Object.fromEntries([
    ['wall', 'concrete', 'sunken'], ['ceiling', 'concrete', 'steel'], ['floor', 'concrete', 'steel'],
    ['metal', 'brushedMetal', 'metal'], ['ink', 'rubber', 'rubber'], ['steel', 'paintedSteel', 'steel'],
    ['light', 'lamp', 'lightKey'], ['accent', 'paintedSteel', 'accent'],
    ['lamp', 'lamp', 'lampGlow'],
  ].map(([name, role, token]) => [name, track(createMaterial(THREE, theme, role, token))]));
  material.light.emissiveIntensity = 3;
  setIndicator(material.lamp, theme, { lit: true });
  const staticRoom = new THREE.Group();
  scene.add(staticRoom);
  const unitBox = track(new THREE.BoxGeometry(1, 1, 1));
  const dummy = new THREE.Object3D();
  function block(parent, size, position, mat, rotation = 0) {
    let geometry = unitBox;
    if (Math.max(...size) > 2 && size.filter(length => length > 0.5).length >= 2) {
      geometry = track(new THREE.BoxGeometry(1, 1, 1, ...size.map(length => Math.max(1, Math.ceil(length / 0.6)))));
    }
    const mesh = new THREE.Mesh(geometry, mat);
    mesh.castShadow = mat === material.metal || mat === material.steel || mat === material.ink;
    mesh.receiveShadow = false;
    mesh.scale.set(...size); mesh.position.set(...position); mesh.rotation.y = rotation;
    parent.add(mesh); return mesh;
  }
  function instance(geometry, mat, poses) {
    const mesh = track(new THREE.InstancedMesh(geometry, mat, poses.length));
    mesh.receiveShadow = mat !== material.light && mat !== material.lamp;
    poses.forEach((p, i) => {
      dummy.position.set(...p.position); dummy.rotation.set(...(p.rotation ?? [0, 0, 0]));
      dummy.scale.set(...(p.scale ?? [1, 1, 1])); dummy.updateMatrix(); mesh.setMatrixAt(i, dummy.matrix);
      if (mat === material.floor) {
        const [x, y, z] = p.position;
        mesh.setColorAt(i, new THREE.Color().setScalar(roomLightAt({ x, y, z }, { x: 0, y: 1, z: 0 })));
      }
    });
    mesh.instanceMatrix.needsUpdate = true;
    scene.add(mesh); return mesh;
  }
  const halfW = ROOM.width / 2, halfD = ROOM.depth / 2;
  block(staticRoom, [ROOM.width, 0.16, ROOM.depth], [0, -FLOOR.thickness - 0.08, 0], material.ceiling);
  block(staticRoom, [ROOM.width, 0.16, ROOM.depth], [0, ROOM.height + 0.08, 0], material.ceiling);
  for (const x of [-halfW, halfW]) block(staticRoom, [0.24, ROOM.height + FLOOR.thickness, ROOM.depth], [x, (ROOM.height - FLOOR.thickness) / 2, 0], material.wall);
  block(staticRoom, [ROOM.width, ROOM.height + FLOOR.thickness, 0.24], [0, (ROOM.height - FLOOR.thickness) / 2, -halfD], material.wall);
  const doorLeft = DOOR.x - DOOR.width / 2, doorRight = DOOR.x + DOOR.width / 2;
  block(staticRoom, [doorLeft + halfW, ROOM.height + FLOOR.thickness, 0.24], [(doorLeft - halfW) / 2, (ROOM.height - FLOOR.thickness) / 2, halfD], material.wall);
  block(staticRoom, [halfW - doorRight, ROOM.height + FLOOR.thickness, 0.24], [(halfW + doorRight) / 2, (ROOM.height - FLOOR.thickness) / 2, halfD], material.wall);
  block(staticRoom, [DOOR.width, ROOM.height - DOOR.height, 0.24], [DOOR.x, (ROOM.height + DOOR.height) / 2, halfD], material.wall);
  for (const x of [3.725, 5.275]) block(staticRoom, [0.3, 2.6, 4], [x, 1.3, 9], material.wall);
  for (const y of [-0.15, 2.6]) block(staticRoom, [1.85, 0.3, 4], [4.5, y, 9], material.wall);
  block(staticRoom, [0.65, 0.04, 1.8], [4.5, 2.42, 9], material.light);
  const tiles = [];
  for (let x = -halfW + FLOOR.tile / 2; x < halfW; x += FLOOR.tile)
    for (let z = -halfD + FLOOR.tile / 2; z < halfD; z += FLOOR.tile)
      tiles.push({ position: [x, -FLOOR.thickness / 2, z], scale: [FLOOR.tile - FLOOR.seam, FLOOR.thickness, FLOOR.tile - FLOOR.seam] });
  instance(unitBox, material.floor, tiles);
  for (let x = -halfW; x <= halfW; x += FLOOR.tile) {
    block(staticRoom, [0.018, 0.02, ROOM.depth], [x, ROOM.height - 0.02, 0], material.metal);
  }
  for (let z = -halfD; z <= halfD; z += FLOOR.tile) {
    block(staticRoom, [ROOM.width, 0.02, 0.018], [0, ROOM.height - 0.02, z], material.metal);
  }
  const lights = [], recesses = [];
  for (const x of CEILING_LIGHTS.xs) for (const z of CEILING_LIGHTS.zs) {
    lights.push({ position: [x, ROOM.height - 0.04, z], rotation: [Math.PI / 2, 0, 0], scale: [CEILING_LIGHTS.width, CEILING_LIGHTS.depth, 1] });
    recesses.push({ position: [x, ROOM.height - 0.01, z], scale: [CEILING_LIGHTS.width + 0.12, 0.04, CEILING_LIGHTS.depth + 0.12] });
  }
  instance(unitBox, material.metal, recesses);
  instance(track(new THREE.PlaneGeometry(1, 1)), material.light, lights);

  function paintedFace(width, height, parent, position, rotation = 0, pxW = 1024, pxH = 512) {
    const surface = document.createElement('canvas'); surface.width = pxW; surface.height = pxH;
    const texture = track(new THREE.CanvasTexture(surface)); texture.colorSpace = THREE.SRGBColorSpace;
    texture.anisotropy = Math.min(4, renderer.capabilities.getMaxAnisotropy());
    const mat = track(createMaterial(THREE, theme, 'paintedSteel', 'lightKey', { map: texture }));
    const mesh = new THREE.Mesh(track(new THREE.PlaneGeometry(width, height, Math.ceil(width / 0.35), Math.ceil(height / 0.35))), mat);
    mesh.position.set(...position); mesh.rotation.y = rotation; parent.add(mesh);
    return { canvas: surface, texture, mesh, signature: '' };
  }
  const alarmMaterials = [false, true].map(lit => {
    const mat = track(createMaterial(THREE, theme, 'lamp', 'lampOff'));
    setIndicator(mat, theme, { lit });
    return mat;
  });
  const alarmBatches = alarmMaterials.map(mat => {
    const mesh = instance(unitBox, mat, Array.from({ length: 22 }, () => ({ position: [0, 0, 0] })));
    mesh.count = 0;
    mesh.frustumCulled = false;
    mesh.receiveShadow = false;
    return mesh;
  });
  const boards = BOARDS.map(config => {
    const group = new THREE.Group(); group.position.set(config.x, 0, config.z); group.rotation.y = config.yaw;
    staticRoom.add(group);
    block(group, [BOARD.width, BOARD.top, 0.18], [0, BOARD.top / 2, -0.11], material.metal);
    const outline = deskOutline(config);
    const deskGeometry = track(new THREE.BoxGeometry(1, 1, 1, 5, 1, 2));
    const positions = deskGeometry.attributes.position;
    for (let i = 0; i < positions.count; i++) {
      const t = positions.getZ(i) + 0.5;
      const left = outline[0].x * (1 - t) + outline[3].x * t;
      const right = outline[1].x * (1 - t) + outline[2].x * t;
      const z = t * BOARD.deskDepth;
      positions.setXYZ(i, left + (positions.getX(i) + 0.5) * (right - left),
        BOARD.deskY + positions.getY(i) * 0.12 - Math.sin(BOARD.slope) * z, z);
    }
    deskGeometry.computeVertexNormals();
    group.add(new THREE.Mesh(deskGeometry, material.steel));
    for (const x of [-1.1, 1.1]) block(group, [0.12, 0.85, 0.65], [x, 0.425, 0.4], material.metal);
    block(group, [BOARD.width, BOARD.top - BOARD.bottom, 0.03], [0, (BOARD.top + BOARD.bottom) / 2, -0.015], material.steel);
    const face = paintedFace(BOARD.width, BOARD.top - BOARD.bottom, group, [0, (BOARD.top + BOARD.bottom) / 2, 0.031], 0, BOARD_PX.width, BOARD_PX.height);
    Object.assign(face.mesh.material, { transparent: true, depthWrite: false });
    face.mesh.renderOrder = 1;
    const layout = boardLayout(config.points.length, config.view);
    group.updateMatrixWorld(true);
    const windows = layout.windows.map(w => {
      const p = boardPoint(config, (w.x + w.w / 2) / BOARD_PX.width * BOARD.width - BOARD.width / 2,
        BOARD.top - (w.y + w.h / 2) / BOARD_PX.height * (BOARD.top - BOARD.bottom), 0.014);
      dummy.position.set(p.x, p.y, p.z);
      dummy.rotation.set(0, config.yaw, 0);
      dummy.scale.set(w.w / BOARD_PX.width * BOARD.width, w.h / BOARD_PX.height * (BOARD.top - BOARD.bottom), 0.022);
      dummy.updateMatrix();
      return dummy.matrix.clone();
    });
    return { ...face, config, windows };
  });
  const meters = createMeters(THREE, scene, theme, { anisotropy: Math.min(4, renderer.capabilities.getMaxAnisotropy()) });
  const screens = [];
  for (const desk of DESKS) {
    block(staticRoom, [desk.w, 0.1, desk.d], [desk.x, 0.76, desk.z], material.steel);
    block(staticRoom, [desk.w * 0.74, 0.012, desk.d * 0.57], [desk.x, 0.817, desk.z + 0.08], material.ink);
    for (const x of [-desk.w / 2 + 0.18, desk.w / 2 - 0.18])
      block(staticRoom, [0.16, 0.73, desk.d - 0.12], [desk.x + x, 0.365, desk.z], material.metal);
    if (!desk.supervisor) for (const offset of [-0.51, 0.51]) {
      block(staticRoom, [0.91, 0.59, 0.1], [desk.x + offset, 1.18, desk.z - 0.13], material.ink);
      block(staticRoom, [0.08, 0.3, 0.12], [desk.x + offset, 0.9, desk.z - 0.17], material.metal);
      const screen = paintedFace(0.85, 0.52, staticRoom, [desk.x + offset, 1.18, desk.z - 0.073]);
      screen.mesh.material.emissive.set(theme.lightKey);
      screen.mesh.material.emissiveMap = screen.texture;
      screen.mesh.material.emissiveIntensity = 0.8;
      screens.push({ ...screen, lastPaint: -Infinity });
    }
  }
  for (const [size, y, dz, mat] of [
    [[0.6, 0.1, 0.58], 0.48, 0, material.ink], [[0.6, 0.6, 0.1], 0.82, 0.25, material.ink],
    [[0.09, 0.42, 0.09], 0.23, 0, material.metal], [[0.66, 0.06, 0.12], 0.06, 0, material.metal],
    [[0.12, 0.06, 0.66], 0.06, 0, material.metal],
  ]) instance(unitBox, mat, CHAIRS.map(c => ({ position: [c.x, y, c.z + dz], scale: size })));
  const signs = [
    { text: 'TO PLANT SPACES', face: paintedFace(1.5, 0.22, staticRoom, [DOOR.x, 2.6, DOOR.z - 0.02], Math.PI, 768, 112) },
    { text: 'CONTAINMENT CAMERA', face: paintedFace(1.7, 0.22, staticRoom, [CCTV.x + 0.02, CCTV.y + 0.66, CCTV.z], Math.PI / 2, 768, 112) },
    { text: 'SHIFT SUPERVISOR', face: paintedFace(1.6, 0.18, staticRoom, [0, 0.62, 6.26], 0, 768, 112) },
  ];
  const plant = createPlantScene({ theme, reducedMotion, environment: environment.texture, anisotropy: Math.min(4, renderer.capabilities.getMaxAnisotropy()) });
  const cctvTarget = track(new THREE.WebGLRenderTarget(480, 270, { type: THREE.HalfFloatType }));
  track(cctvTarget.texture);
  cctvTarget.texture.colorSpace = THREE.LinearSRGBColorSpace;
  const cctvMat = track(createMaterial(THREE, theme, 'paintedSteel', 'lightKey', {
    map: cctvTarget.texture, emissiveMap: cctvTarget.texture, emissive: theme.lightKey, emissiveIntensity: 0.8,
  }));
  block(staticRoom, [0.12, CCTV.height + 0.16, CCTV.width + 0.16], [CCTV.x - 0.01, CCTV.y, CCTV.z], material.ink);
  const cctvScreen = new THREE.Mesh(track(new THREE.PlaneGeometry(CCTV.width, CCTV.height)), cctvMat);
  cctvScreen.rotation.y = Math.PI / 2; cctvScreen.position.set(CCTV.x + 0.06, CCTV.y, CCTV.z); staticRoom.add(cctvScreen);
  mergeStatic(staticRoom, { add: track });
  staticRoom.traverse(mesh => {
    if (mesh.isMesh && !mesh.material.emissiveMap) bakeRoomGeometry(THREE, mesh);
  });

  // Device coordinates follow the sloped desk, with their fronts toward the operator.
  const placements = devicePlacements(KNOBS);
  const hitMaterial = track(createMaterial(THREE, theme, 'rubber', 'rubber', { visible: false }));
  const devices = knobIds.map((id, i) => {
    const placement = placements.find(p => p.id === id);
    const p = placement.position;
    const frame = new THREE.Group();
    frame.position.set(p.x, p.y, p.z);
    frame.rotation.set(BOARD.slope, placement.yaw, 0, 'YXZ');
    frame.scale.setScalar(0.25);
    frame.translateY(0.065); frame.updateMatrix(); scene.add(frame);
    const kind = knobKinds[i];
    const label = paintedFace(0.6, 0.16, frame, [0, 0.117, -0.311], 0, 768, 192);
    label.mesh.rotation.x = -0.22; label.mesh.userData.device = i;
    const hit = block(frame, [0.66, 0.32, 0.66], [0, 0.1, 0], hitMaterial);
    hit.userData.device = i;
    hit.userData.hitVolume = true;
    const device = { id, kind, frame, label, index: i };
    if (kind === 'dial' || kind === 'rotary') {
      const size = 0.4;
      device.skirt = paintedFace(size, size, frame, [0, 0.025, -0.02], 0, 512, 512);
      device.skirt.mesh.rotation.x = -Math.PI / 2; device.skirt.mesh.userData.device = i;
    }
    return device;
  });
  const cylinder = track(new THREE.CylinderGeometry(1, 1, 1, 16));
  const statusMaterial = track(createMaterial(THREE, theme, 'lamp', 'lightKey'));
  const batches = [];
  function batch(geometry, mat, entries) {
    const mesh = instance(geometry, mat, entries.map(() => ({ position: [0, 0, 0] })));
    mesh.castShadow = mat !== statusMaterial;
    mesh.userData.devices = entries.map(e => e.device.index);
    batches.push({ mesh, entries });
    return mesh;
  }
  const entries = (filter, parts) => devices.filter(filter).flatMap(device => parts(device).map(part => ({ device, ...part })));
  const all = () => true;
  const turning = d => d.kind === 'dial' || d.kind === 'rotary';
  const switches = d => d.kind === 'switch';
  const buttons = d => d.kind === 'button';
  batch(unitBox, material.metal, entries(all, () => [{ position: [0, 0.115, -0.32], rotation: [-0.22, 0, 0], scale: [0.62, 0.18, 0.018] }]));
  batch(cylinder, material.metal, entries(all, d => [{
    position: [0, 0.013, -0.02], scale: [turning(d) ? 0.21 : 0.14, 0.025, turning(d) ? 0.21 : 0.14],
  }]));
  batch(cylinder, material.ink, entries(turning, d => [{
    position: [0, 0.08, -0.02], scale: [d.kind === 'dial' ? 0.14 : 0.12, 0.11, d.kind === 'dial' ? 0.14 : 0.12],
  }]));
  batch(unitBox, material.steel, entries(turning, () => [{ part: 'pointer' }]));
  batch(cylinder, material.ink, entries(switches, () => [{ position: [0, 0.045, -0.02], scale: [0.08, 0.07, 0.08] }]));
  batch(unitBox, material.ink, entries(switches, () => [{ part: 'grip' }, { part: 'heel' }]));
  batch(unitBox, material.metal, entries(buttons, d => d.id === 'manual-trip' ? [] : [{ position: [0, 0.04, -0.02], scale: [0.22, 0.06, 0.22] }]));
  const lenses = entries(switches, () => [-1, 1].map(side => ({ side, part: 'lamp', position: [side * 0.10, 0.036, -0.205], scale: [0.039, 0.024, 0.039] })));
  batch(cylinder, material.metal, lenses.map(e => ({ ...e, part: null, scale: [0.05, 0.025, 0.05], position: [e.position[0], 0.015, e.position[2]] })));
  batch(cylinder, statusMaterial, lenses);
  batch(unitBox, statusMaterial, entries(buttons, d => d.id === 'manual-trip' ? [] : [{ part: 'button' }]));
  const tripMaterial = track(createMaterial(THREE, theme, 'rubber', 'hotCoolant'));
  batch(cylinder, material.metal, entries(d => d.id === 'manual-trip', () => [{ position: [0, 0.08, -0.02], scale: [0.045, 0.12, 0.045] }]));
  batch(cylinder, tripMaterial, entries(d => d.id === 'manual-trip', () => [{ part: 'mushroom' }]));
  batch(cylinder, statusMaterial, entries(all, () => [{
    part: 'pending', position: [0.25, 0.117, -0.296],
    rotation: [Math.PI / 2 - 0.22, 0, 0], scale: [0.017, 0.015, 0.017],
  }]));
  const trip = devices.find(d => d.id === 'manual-trip');
  const cover = new THREE.Group();
  const glass = track(createMaterial(THREE, theme, 'glass', 'steam', { transparent: true, opacity: 0.26, depthWrite: false, side: THREE.DoubleSide }));
  glass.forceSinglePass = true;
  block(cover, [0.32, 0.012, 0.35], [0, 0.205, 0.175], glass);
  for (const x of [-0.16, 0.16]) block(cover, [0.009, 0.20, 0.35], [x, 0.10, 0.175], glass);
  block(cover, [0.32, 0.20, 0.009], [0, 0.10, 0.35], glass);
  // Thin rails and a hinge make the clear guard readable against the desk.
  for (const x of [-0.16, 0.16]) block(cover, [0.012, 0.012, 0.35], [x, 0.212, 0.175], material.metal);
  block(cover, [0.33, 0.012, 0.012], [0, 0.212, 0.35], material.metal);
  block(cover, [0.36, 0.035, 0.035], [0, 0.01, 0], material.metal);
  mergeStatic(cover, { add: track });
  cover.position.set(0, 0.025, -0.19); trip.frame.add(cover);
  cover.traverse(mesh => { if (mesh.isMesh) { mesh.userData.device = trip.index; mesh.userData.cover = true; } });
  const localMatrix = new THREE.Matrix4();
  const tint = new THREE.Color();
  const raycaster = new THREE.Raycaster(), pointer = new THREE.Vector2();
  let hovered = null, grabbed = null;

  let palette = theme, view = null, text = null, knobStates = [];
  let pose = { ...STANDING_SPOTS[DEFAULT_VIEW] }, selected = DEFAULT_VIEW, glide = null;
  const shown = new Map(), keys = new Set(), renderTimes = [], frameTimes = [];
  let disposed = false, visible = true, raf = 0, timer = 0, last = 0, lastCctv = -Infinity;
  let lastPlant = 0, plantDirty = true, plantMoving = false, themeDirty = true;
  let dragging = false, dragDistance = 0, pointerX = 0, pointerY = 0;
  let space = 'control-room';
  let fadeAt = -Infinity;
  const isPlant = () => space !== 'control-room';
  const collisions = () => isPlant() ? plant.obstacles[space] : COLLISIONS;
  function enterSpace(next, now) {
    if (next === space) return;
    space = next;
    fadeAt = now;
    camera.layers.set(0);
    if (space === 'reactor' || space === 'airlock') {
      camera.layers.set(1);
      camera.layers.enable(4);
    } else if (space !== 'control-room') {
      camera.layers.set(2);
      camera.layers.enable(3);
      camera.layers.enable(4);
    }
    const names = { 'control-room': 'Control room', corridor: 'Plant corridor', turbine: 'Turbine hall', airlock: 'Personnel airlock', reactor: 'Containment operating deck' };
    container.dataset.view = names[space];
    canvas.setAttribute('aria-label', `${names[space]}. First-person control room and plant views. The text section lists the same values.`);
  }

  function applyTheme(next) {
    palette = next;
    scene.background = new THREE.Color(palette.sunken);
    lighting.setTheme(palette);
    alarmMaterials.forEach((mat, index) => setIndicator(mat, palette, { lit: index === 1 }));
    cctvMat.emissive.set(palette.lightKey);
    screens.forEach(screen => screen.mesh.material.emissive.set(palette.lightKey));
    Object.values(material).forEach(mat => applyMaterialPalette(mat, palette));
    material.light.emissive.set(palette.lightKey);
    setIndicator(material.lamp, palette, { lit: true });
    plant.setTheme(next); meters.setTheme(next); themeDirty = true; plantDirty = true;
    boards.forEach(b => { b.signature = ''; }); screens.forEach(s => { s.signature = ''; });
    for (const sign of signs) paintSign(sign.face, sign.text);
    applyMaterialPalette(tripMaterial, palette); applyMaterialPalette(glass, palette);
    // Instance colors carry the lamp palette without a material per lens.
    statusMaterial.color.set(palette.lightKey);
    for (const device of devices) {
      device.label.signature = '';
      if (device.skirt) paintSkirt(device);
    }
  }
  function paintSign(face, label) {
    const ctx = face.canvas.getContext('2d'); ctx.fillStyle = palette.surface; ctx.fillRect(0, 0, face.canvas.width, face.canvas.height);
    paintText(ctx, label, { x: 8, y: 0, w: face.canvas.width - 16, h: face.canvas.height, font: 40 }, palette.ink);
    face.texture.needsUpdate = true;
  }
  function resize() {
    const width = Math.max(1, container.clientWidth), height = Math.max(1, container.clientHeight);
    renderer.setSize(width, height, false);
    for (const c of [camera, plant.camera]) { c.aspect = width / height; c.updateProjectionMatrix(); }
    const segment = BOARDS.find(board => board.view === selected);
    if (segment) {
      pose = { ...STANDING_SPOTS[selected], ...fitSpot(segment, camera.aspect, STANDING_SPOTS[selected].fov) };
      glide = null;
    }
    requestFrame();
  }
  const resizeObserver = new ResizeObserver(resize); resizeObserver.observe(container);
  const visibilityObserver = new IntersectionObserver(entries => {
    visible = entries.some(e => e.isIntersecting);
    if (visible) requestFrame();
    else { cancelAnimationFrame(raf); raf = 0; clearTimeout(timer); timer = 0; keys.clear(); }
  }); visibilityObserver.observe(container);

  function requestFrame() {
    if (disposed || !visible || raf) return;
    clearTimeout(timer); timer = 0;
    last = performance.now(); raf = requestAnimationFrame(frame);
  }
  function render(renderScene, renderCamera) {
    const start = performance.now(); renderer.render(renderScene, renderCamera);
    renderTimes.push(performance.now() - start); if (renderTimes.length > 30) renderTimes.shift();
    container.dataset.drawCalls = String(renderer.info.render.calls);
    container.dataset.triangles = String(renderer.info.render.triangles);
    container.dataset.renderMs = (renderTimes.reduce((a, b) => a + b, 0) / renderTimes.length).toFixed(1);
    container.dataset.pixelRatio = String(pixelRatio);
  }
  function frame(now) {
    raf = 0; if (disposed || !visible) return;
    const frameStart = performance.now();
    const dt = Math.min(0.1, (now - last) / 1000); last = now;
    if (glide) {
      pose = reducedMotion() ? { ...glide.end } : glidePose(glide.start, glide.end, glide.path, (now - glide.at) / 1000);
      if (reducedMotion() || now - glide.at >= 800) { pose = { ...glide.end }; glide = null; }
    }
    const delta = walkDelta(keys, pose.yaw, dt);
    const previous = pose;
    pose = walk(pose, delta.x, delta.z, collisions(), ROOM.radius);
    enterSpace(doorwayCrossing(space, previous, pose, DOORWAYS, ROOM.radius), now);
    const opacity = doorwayFade(now - fadeAt, reducedMotion());
    canvas.style.opacity = String(Math.round(opacity * 1000) / 1000);
    const walking = pose.x !== previous.x || pose.z !== previous.z;
    if (walking) selected = null;
    camera.position.set(pose.x, ROOM.eye, pose.z);
    camera.rotation.set(pose.pitch, pose.yaw, 0, 'YXZ');
    if (camera.fov !== pose.fov) {
      camera.fov = pose.fov;
      camera.updateProjectionMatrix();
    }
    const needlesMoving = !isPlant() && easeNeedles(dt);
    if (!isPlant()) { meters.update(view?.pairs ?? [], shown); paintBoards(now); paintScreens(now); }
    placeKnobs(now);
    renderer.info.reset();
    if (isPlant() || now - lastCctv >= 200) {
      plantMoving = plant.advance(Math.min(0.25, (now - lastPlant) / 1000)); lastPlant = now;
      if (!isPlant()) {
        renderer.setRenderTarget(cctvTarget); render(plant.scene, plant.cctvCamera); renderer.setRenderTarget(null);
        lastCctv = now;
      }
      plantDirty = false;
    }
    container.dataset.camera = glide || walking || dragging ? 'moving' : 'still';
    render(isPlant() ? plant.scene : scene, camera);
    // Renderer counters include the containment pass as well as the room.
    frameTimes.push(performance.now() - frameStart); if (frameTimes.length > 30) frameTimes.shift();
    const mean = frameTimes.reduce((a, b) => a + b, 0) / frameTimes.length;
    if (pixelRatio > 1 && frameTimes.length === 30 && mean > 20) { pixelRatio = 1; renderer.setPixelRatio(pixelRatio); resize(); }
    const flashing = !reducedMotion() && (view?.alarms.some(a => a.state === 'active') || knobStates.some(s => s.pending || s.refusedUntil > now));
    if (opacity < 1 || glide || walking || needlesMoving || (isPlant() && plantMoving) || (!isPlant() && flashing)) {
      if (!raf) raf = requestAnimationFrame(frame);
    } else if (!isPlant()) {
      const waitingScreen = screens.some(s => s.pending);
      if (plantMoving || plantDirty || waitingScreen) timer = setTimeout(requestFrame, Math.max(1, 200 - (performance.now() - lastCctv)));
    }
  }

  function easeNeedles(dt) {
    if (!view) return false;
    const k = reducedMotion() ? 1 : 1 - Math.exp(-dt / 0.22);
    let moving = false;
    for (const pair of view.pairs) {
      const goal = { reported: pair.reported, truth: pair.trueValue };
      const current = shown.get(pair.key) ?? goal;
      const next = {};
      for (const key of ['reported', 'truth']) {
        const eased = current[key] === null || goal[key] === null ? goal[key] : current[key] + (goal[key] - current[key]) * k;
        next[key] = Math.abs(goal[key] - eased) < (pair.range[1] - pair.range[0]) * 0.001 ? goal[key] : eased;
        if (next[key] !== goal[key]) moving = true;
      }
      shown.set(pair.key, next);
    }
    return moving;
  }
  function paintBoards(now) {
    for (const mesh of alarmBatches) mesh.count = 0;
    for (const board of boards) {
      const layout = boardLayout(board.config.points.length, board.config.view);
      const states = layout.windows.map(w => windowState(view?.alarms.find(a => a.key === w.key)?.state, now, reducedMotion()));
      states.forEach((state, index) => {
        const mesh = alarmBatches[Number(state.lit)];
        mesh.setMatrixAt(mesh.count++, board.windows[index]);
      });
      const signature = JSON.stringify([text?.plantTime, text?.telemetry, states]);
      if (signature === board.signature && !themeDirty) continue;
      board.signature = signature;
      const ctx = board.canvas.getContext('2d');
      ctx.clearRect(0, 0, BOARD_PX.width, BOARD_PX.height);
      ctx.fillStyle = palette.steel;
      ctx.fillRect(0, 0, BOARD_PX.width, layout.header.h);
      paintText(ctx, board.config.title, layout.text.title, palette.ink, 'left');
      paintText(ctx, text ? `Plant time ${text.plantTime}` : 'Waiting for snapshot', layout.text.time, palette.ink, 'left');
      paintText(ctx, text?.telemetry ?? 'No telemetry received', layout.text.telemetry, palette.ink, 'left');
      ctx.strokeStyle = palette.strongLine;
      ctx.lineWidth = 2;
      ctx.strokeRect(0, 150, BOARD_PX.width, 80);
      layout.windows.forEach((w, i) => {
        const state = states[i];
        ctx.strokeStyle = palette.ink; ctx.lineWidth = 2;
        ctx.strokeRect(w.x - 2, w.y - 2, w.w + 4, w.h + 4);
        ctx.strokeStyle = state.lit ? palette.lampInk : palette.lampLegend;
        ctx.strokeRect(w.x + 1, w.y + 1, w.w - 2, w.h - 2);
        const lines = wrapLines(ctx, w.engraved, w.w - 8, w.font);
        const lineHeight = w.font * 1.3;
        lines.forEach((line, j) => paintText(ctx, line, {
          x: w.x + 4, y: w.y + (w.h - lines.length * lineHeight) / 2 + j * lineHeight,
          w: w.w - 8, h: lineHeight, font: w.font,
        }, state.lit ? palette.lampInk : palette.lampLegend));
        if (state.mark) { ctx.fillStyle = palette.lampInk; ctx.fillRect(w.x + w.w - 9, w.y + 3, 6, 6); }
      });
      // Hot flow runs to the steam generators; cold flow returns to the pumps.
      for (const line of mimicLines(board.config)) {
        ctx.strokeStyle = palette[line.color];
        ctx.lineWidth = 3;
        ctx.beginPath();
        ctx.moveTo(line.start, line.y);
        ctx.lineTo(line.end, line.y);
        for (const x of [line.start + 20, line.end - 20]) {
          ctx.moveTo(x - line.direction * 10, line.y - 6);
          ctx.lineTo(x, line.y);
          ctx.lineTo(x - line.direction * 10, line.y + 6);
        }
        ctx.stroke();
      }
      board.texture.needsUpdate = true;
    }
    for (const mesh of alarmBatches) mesh.instanceMatrix.needsUpdate = true;
    themeDirty = false;
  }
  function paintScreens(now) {
    if (!view) return;
    screens.forEach((screen, i) => {
      const points = view.pairs.filter((_, index) => index % 4 === i);
      const rs = view.reportedStatus;
      const lines = [view.telemetry.quiet ? 'TELEMETRY QUIET · HELD' : 'REPORTED PLANT MIMIC',
        ...points.map(p => `${p.label}  ${formatValue(p.reported, p.unit)}`),
        ...rs.coolantPumpsRunning.map((on, j) => `Coolant pump ${j ? 'B' : 'A'}: ${on ? 'running' : 'stopped'}`),
        ...rs.feedPumpsRunning.map((on, j) => `Feed pump ${j ? 'B' : 'A'}: ${on ? 'running' : 'stopped'}`),
        `Reactor: ${rs.reactorTripped ? 'TRIPPED' : 'not tripped'} · Turbine: ${rs.turbineTripped ? 'TRIPPED' : 'not tripped'}`];
      const signature = lines.join('\n'); screen.pending = signature !== screen.signature;
      if (!screen.pending || now - screen.lastPaint < 1000) return;
      screen.signature = signature; screen.pending = false; screen.lastPaint = now;
      const ctx = screen.canvas.getContext('2d'); ctx.fillStyle = palette.surface; ctx.fillRect(0, 0, 1024, 512);
      // A simple process line connects the reported points and equipment states.
      ctx.strokeStyle = palette.strongLine; ctx.lineWidth = 4; ctx.beginPath(); ctx.moveTo(18, 58); ctx.lineTo(18, 480); ctx.stroke();
      lines.forEach((line, j) => paintText(ctx, line, { x: 32, y: 6 + j * 39, w: 970, h: 38, font: 26 }, palette.ink, 'left'));
      screen.texture.needsUpdate = true;
    });
  }
  function paintSkirt(device) {
    const ctx = device.skirt.canvas.getContext('2d');
    ctx.fillStyle = palette.surface; ctx.fillRect(0, 0, 512, 512);
    const sweep = device.kind === 'dial' ? 300 : 240;
    const steps = device.kind === 'dial' ? 10 : 4;
    ctx.strokeStyle = palette.ink; ctx.lineWidth = 3;
    for (let i = 0; i <= steps; i++) {
      const angle = (i / steps - 0.5) * sweep * Math.PI / 180;
      const x = Math.sin(angle), y = -Math.cos(angle);
      ctx.beginPath(); ctx.moveTo(256 + x * 178, 256 + y * 178); ctx.lineTo(256 + x * 195, 256 + y * 195); ctx.stroke();
      paintText(ctx, String(i * 100 / steps), { x: 256 + x * 220 - 30, y: 256 + y * 220 - 16, w: 60, h: 32, font: 26 }, palette.ink);
    }
    paintText(ctx, '%', { x: 220, y: 390, w: 72, h: 38, font: 28 }, palette.ink);
    device.skirt.texture.needsUpdate = true;
  }

  function placeKnobs(now) {
    for (const { mesh, entries } of batches) {
      entries.forEach((entry, i) => {
        const { device, part } = entry, state = knobStates[device.index];
        dummy.position.set(...(entry.position ?? [0, 0, 0]));
        dummy.rotation.set(...(entry.rotation ?? [0, 0, 0])); dummy.scale.set(...(entry.scale ?? [1, 1, 1]));
        let color = palette.lampOff;
        if (part === 'pointer') {
          const angle = ((state?.fraction ?? 0) - 0.5) * (state?.sweep ?? (device.kind === 'dial' ? 300 : 240)) * Math.PI / 180;
          dummy.position.set(Math.sin(angle) * 0.052, 0.139, -0.02 - Math.cos(angle) * 0.052);
          dummy.rotation.y = -angle; dummy.scale.set(0.016, 0.01, 0.10);
        } else if (part === 'grip' || part === 'heel') {
          const angle = ((state?.travel ?? 0) * 2 - 1) * 0.7;
          const offset = part === 'heel' ? -0.025 : 0.035;
          dummy.position.set(-Math.sin(angle) * offset, part === 'heel' ? 0.17 : 0.10, -0.02 + Math.cos(angle) * offset);
          dummy.rotation.y = -angle;
          dummy.scale.set(...(part === 'heel' ? [0.065, 0.05, 0.32] : [0.05, 0.13, 0.08]));
        } else if (part === 'lamp') {
          const lit = state && typeof state.green === 'boolean' && (entry.side === 1 ? state.green : !state.green);
          color = lit ? (entry.side === 1 ? palette.controlGreen : palette.accent) : palette.lampOff;
        } else if (part === 'button' || part === 'mushroom') {
          dummy.position.set(0, (part === 'mushroom' ? 0.15 : 0.085) - (state?.depth ?? 0) * 0.035, -0.02);
          dummy.scale.set(...(part === 'mushroom' ? [0.12, 0.065, 0.12] : [0.18, 0.045, 0.18]));
          const lit = device.id === 'reset-trip' ? view?.reportedStatus.reactorTripped : view?.alarms.some(a => a.state === 'active');
          color = lit ? palette.lampGlow : palette.lampOff;
        } else if (part === 'pending') {
          color = state?.pending && (reducedMotion() || Math.floor(now / 300) % 2 === 0) ? palette.lampGlow : palette.lampOff;
        }
        dummy.updateMatrix(); localMatrix.multiplyMatrices(device.frame.matrix, dummy.matrix); mesh.setMatrixAt(i, localMatrix);
        if (mesh.material === statusMaterial) mesh.setColorAt(i, tint.set(color));
      });
      mesh.instanceMatrix.needsUpdate = true;
      if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
      mesh.computeBoundingSphere();
    }
    cover.rotation.x = knobStates[trip.index]?.cover?.open ? -1.35 : 0;
    for (const device of devices) {
      const state = knobStates[device.index];
      const focused = state?.focused || hovered?.index === device.index || grabbed?.index === device.index;
      const refused = state?.refusedUntil > now && (reducedMotion() || Math.floor(now / 250) % 2 === 0);
      const detail = !state ? 'WAITING FOR SNAPSHOT' : device.kind === 'switch'
        ? (state.mode ? 'MANUAL / AUTOMATIC' : 'OFF / ON')
        : device.kind === 'button' ? device.id === 'manual-trip'
          ? state.cover.open ? state.cover.fired ? 'CLOSE COVER TO REARM' : 'COVER OPEN · PRESS TO TRIP' : 'LIFT COVER TO ARM'
          : device.id === 'reset-trip' ? 'RESET' : 'ACK'
        : `${state.value}% SETPOINT`;
      const signature = JSON.stringify([focused, refused, detail]);
      if (device.label.signature === signature) continue;
      device.label.signature = signature;
      const ctx = device.label.canvas.getContext('2d');
      const bg = refused ? palette.warning : focused ? palette.ink : palette.steel;
      const fg = refused || focused ? palette.surface : palette.ink;
      ctx.fillStyle = bg; ctx.fillRect(0, 0, 768, 192);
      ctx.strokeStyle = fg; ctx.lineWidth = focused ? 9 : 3; ctx.strokeRect(6, 6, 756, 180);
      paintText(ctx, knobLabels[device.index], { x: 16, y: 12, w: 690, h: 90, font: 44 }, fg);
      paintText(ctx, detail, { x: 16, y: 108, w: 690, h: 66, font: 26 }, fg);
      device.label.texture.needsUpdate = true;
    }
  }

  function hitDevice(event) {
    if (isPlant()) return null;
    const rect = canvas.getBoundingClientRect();
    pointer.set((event.clientX - rect.left) / rect.width * 2 - 1, 1 - (event.clientY - rect.top) / rect.height * 2);
    scene.updateMatrixWorld(true); camera.updateMatrixWorld(true);
    raycaster.setFromCamera(pointer, camera);
    const hits = raycaster.intersectObjects(scene.children, true);
    const surface = hits.find(hit => !hit.object.userData.hitVolume);
    let hit = surface;
    const proxy = hits.find(hit => hit.object.userData.hitVolume);
    const surfaceDevice = surface?.object.userData.device ?? surface?.object.userData.devices?.[surface?.instanceId];
    if (surfaceDevice === undefined && proxy && (!surface || proxy.distance < surface.distance)) hit = proxy;
    if (!hit) return null;
    const index = hit.object.userData.device ?? hit.object.userData.devices?.[hit.instanceId];
    if (index === undefined) return null;
    return { index, cover: Boolean(hit.object.userData.cover) };
  }
  function deviceSample(index, event) {
    const rect = canvas.getBoundingClientRect();
    const center = new THREE.Vector3(0, 0.08, -0.02);
    devices[index].frame.localToWorld(center); center.project(camera);
    const x = rect.left + (center.x + 1) * rect.width / 2;
    const y = rect.top + (1 - center.y) * rect.height / 2;
    return { angle: Math.atan2(event.clientY - y, event.clientX - x) * 180 / Math.PI, time: event.timeStamp };
  }
  function cancelGrab() {
    if (!grabbed) return;
    const active = grabbed; grabbed = null;
    onDevice(knobIds[active.index], 'cancel');
    if (canvas.hasPointerCapture?.(active.pointerId)) canvas.releasePointerCapture(active.pointerId);
    canvas.style.cursor = '';
  }
  function paintText(ctx, value, box, color, align = 'center') {
    paintLetters(ctx, value, box, color, align);
  }

  function setView(name) {
    if (!(name in STANDING_SPOTS) && name !== 'reactor' && name !== 'turbine') return;
    cancelGrab(); hovered = null; canvas.style.cursor = '';
    selected = name;
    keys.clear();
    dragging = false;
    if (document.pointerLockElement === canvas) document.exitPointerLock();
    const destination = name === 'reactor' || name === 'turbine' ? name : 'control-room';
    const changedSpace = destination !== space;
    if (destination !== 'control-room') {
      const view = VIEWS[name];
      const dx = view.look[0] - view.eye[0];
      const dz = view.look[2] - view.eye[2];
      pose = { x: view.eye[0], z: view.eye[2], yaw: Math.atan2(-dx, -dz),
        pitch: Math.atan2(view.look[1] - ROOM.eye, Math.hypot(dx, dz)), fov: 64 };
      glide = null;
    } else {
      const segment = BOARDS.find(board => board.view === name);
      const spot = STANDING_SPOTS[name];
      const end = segment ? { ...spot, ...fitSpot(segment, camera.aspect, spot.fov) } : spot;
      const path = changedSpace ? null : walkPath(pose, end, COLLISIONS, ROOM.radius);
      if (changedSpace || reducedMotion() || !path) {
        pose = { ...end };
        glide = null;
      } else {
        glide = { start: { ...pose }, end, path, at: performance.now() };
      }
    }
    enterSpace(destination, performance.now());
    const label = STANDING_SPOTS[name]?.name ?? (name === 'reactor' ? 'Containment operating deck' : 'Turbine hall');
    container.dataset.view = label;
    canvas.setAttribute('aria-label', `${label}. First-person control room and plant views. The text section lists the same values.`);
    requestFrame();
  }
  const walkingKeys = new Set(['KeyW', 'KeyA', 'KeyS', 'KeyD', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight']);
  listen(canvas, 'keydown', event => {
    if (document.activeElement !== canvas || grabbed || !walkingKeys.has(event.code) || event.ctrlKey || event.metaKey || event.altKey) return;
    event.preventDefault(); keys.add(event.code); glide = null; requestFrame();
  });
  listen(canvas, 'keyup', event => { if (keys.delete(event.code)) { event.preventDefault(); requestFrame(); } });
  const stop = () => { cancelGrab(); keys.clear(); dragging = false; requestFrame(); };
  listen(canvas, 'blur', stop); listen(window, 'blur', stop);
  listen(document, 'pointerlockchange', () => { if (document.pointerLockElement !== canvas) stop(); });
  listen(canvas, 'pointerdown', event => {
    if (event.button !== 0 || grabbed) return;
    const hit = hitDevice(event);
    if (hit) {
      if (document.pointerLockElement === canvas) document.exitPointerLock();
      canvas.focus(); keys.clear(); glide = null; dragging = false;
      if (hit.cover && knobStates[hit.index]?.cover?.open) {
        onDevice(knobIds[hit.index], 'close'); requestFrame(); return;
      }
      if (onDevice(knobIds[hit.index], 'down', deviceSample(hit.index, event))) {
        grabbed = { ...hit, pointerId: event.pointerId }; hovered = hit;
        canvas.setPointerCapture?.(event.pointerId); canvas.style.cursor = 'grabbing';
      }
      requestFrame(); return;
    }
    canvas.focus(); dragging = true; dragDistance = 0; pointerX = event.clientX; pointerY = event.clientY;
    canvas.setPointerCapture?.(event.pointerId); glide = null;
  });
  listen(document, 'pointermove', event => {
    if (grabbed) {
      if (event.pointerId === grabbed.pointerId) onDevice(knobIds[grabbed.index], 'move', deviceSample(grabbed.index, event));
      requestFrame(); return;
    }
    const locked = document.pointerLockElement === canvas;
    if (!dragging && !locked && event.target === canvas) {
      hovered = hitDevice(event);
      canvas.style.cursor = hovered ? knobStates[hovered.index]?.disabled ? 'not-allowed' : 'grab' : '';
      requestFrame();
    }
    if (!dragging && !locked) return;
    const dx = locked ? event.movementX : event.clientX - pointerX, dy = locked ? event.movementY : event.clientY - pointerY;
    pointerX = event.clientX; pointerY = event.clientY; dragDistance += Math.abs(dx) + Math.abs(dy);
    pose = look(pose, dx, dy); requestFrame();
  });
  listen(canvas, 'pointerup', event => {
    if (grabbed) {
      if (event.pointerId !== grabbed.pointerId) return;
      const active = grabbed; grabbed = null;
      onDevice(knobIds[active.index], 'up', deviceSample(active.index, event));
      if (canvas.hasPointerCapture?.(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
      canvas.style.cursor = 'grab'; requestFrame(); return;
    }
    if (!dragging) return;
    dragging = false;
    if (canvas.hasPointerCapture?.(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    if (dragDistance < 4 && document.pointerLockElement !== canvas) {
      try { canvas.requestPointerLock?.()?.catch?.(() => {}); } catch { /* Drag look remains available. */ }
    }
    requestFrame();
  });
  listen(canvas, 'pointercancel', stop);
  listen(canvas, 'lostpointercapture', cancelGrab);
  listen(canvas, 'pointerleave', () => { if (!grabbed) { hovered = null; canvas.style.cursor = ''; requestFrame(); } });
  listen(canvas, 'keydown', event => { if (event.key === 'Escape') stop(); });
  applyTheme(theme); resize(); setView(DEFAULT_VIEW);
  return {
    update(nextView, nextText, nextKnobs) { view = nextView; text = nextText; knobStates = nextKnobs; requestFrame(); },
    updatePlant(snapshot) { plant.update(snapshot); plantDirty = true; requestFrame(); },
    setTheme(next) { applyTheme(next); requestFrame(); }, setView,
    dispose() {
      if (disposed) return;
      disposed = true; cancelAnimationFrame(raf); clearTimeout(timer);
      if (document.pointerLockElement === canvas) document.exitPointerLock();
      listeners.forEach(remove => remove()); resizeObserver.disconnect(); visibilityObserver.disconnect();
      meters.dispose(); plant.dispose(); lighting.dispose(); scene.environment = null; scene.clear();
      resources.forEach(resource => resource.dispose()); renderer.dispose(); renderer.forceContextLoss(); canvas.remove();
      for (const key of ['drawCalls', 'triangles', 'renderMs', 'pixelRatio', 'view', 'camera']) delete container.dataset[key];
    },
  };
}

function wrapLines(ctx, text, width, font) {
  ctx.font = `600 ${font}px ${FONT}`;
  const lines = []; let line = '';
  for (const word of text.split(' ')) {
    const next = line ? `${line} ${word}` : word;
    if (line && ctx.measureText(next).width > width) { lines.push(line); line = word; } else line = next;
  }
  if (line) lines.push(line);
  return lines;
}
