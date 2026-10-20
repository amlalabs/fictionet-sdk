// One stage owns the renderer, the room camera, and the live containment feed.
import * as THREE from '/vendor/three/build/three.module.js';
import { formatValue } from './instruments.mjs';
import { createMeters } from './meters.mjs';
import { ROOM, FLOOR, CEILING_LIGHTS, DEFAULT_VIEW, BOARD, BOARDS, BOARD_PX, DESKS, CHAIRS, CCTV, DOOR, COLLISIONS, STANDING_SPOTS,
  boardPoint, boardLayout, windowState } from './board-layout.mjs';
import { look, walk, walkDelta, walkPath, glidePose } from './room-motion.mjs';
import { createPlantScene, mergeStatic } from './plant-scene.mjs';
import { createRenderer, createEnvironment, createLighting, createMaterial, applyMaterialPalette, setIndicator } from './look.mjs';

const NEEDLE_SWEEP = 270 * Math.PI / 180;
const FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif";

export function createControlBoard(container, { knobIds, knobLabels, theme, reducedMotion }) {
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
  const camera = new THREE.PerspectiveCamera(ROOM.fov, 1, 0.05, 100);
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
    const mesh = new THREE.Mesh(unitBox, mat);
    mesh.castShadow = mat === material.metal || mat === material.steel || mat === material.ink;
    mesh.receiveShadow = mat !== material.light;
    mesh.scale.set(...size); mesh.position.set(...position); mesh.rotation.y = rotation;
    parent.add(mesh); return mesh;
  }
  function instance(geometry, mat, poses) {
    const mesh = track(new THREE.InstancedMesh(geometry, mat, poses.length));
    mesh.receiveShadow = mat !== material.light && mat !== material.lamp;
    poses.forEach((p, i) => {
      dummy.position.set(...p.position); dummy.rotation.set(...(p.rotation ?? [0, 0, 0]));
      dummy.scale.set(...(p.scale ?? [1, 1, 1])); dummy.updateMatrix(); mesh.setMatrixAt(i, dummy.matrix);
    });
    mesh.instanceMatrix.needsUpdate = true;
    scene.add(mesh); return mesh;
  }
  const halfW = ROOM.width / 2, halfD = ROOM.depth / 2;
  block(staticRoom, [ROOM.width, 0.16, ROOM.depth], [0, -FLOOR.thickness - 0.08, 0], material.ceiling);
  block(staticRoom, [ROOM.width, 0.16, ROOM.depth], [0, ROOM.height + 0.08, 0], material.ceiling);
  for (const x of [-halfW, halfW]) block(staticRoom, [0.24, ROOM.height, ROOM.depth], [x, ROOM.height / 2, 0], material.wall);
  block(staticRoom, [ROOM.width, ROOM.height, 0.24], [0, ROOM.height / 2, -halfD], material.wall);
  const doorLeft = DOOR.x - DOOR.width / 2, doorRight = DOOR.x + DOOR.width / 2;
  block(staticRoom, [doorLeft + halfW, ROOM.height, 0.24], [(doorLeft - halfW) / 2, ROOM.height / 2, halfD], material.wall);
  block(staticRoom, [halfW - doorRight, ROOM.height, 0.24], [(halfW + doorRight) / 2, ROOM.height / 2, halfD], material.wall);
  block(staticRoom, [DOOR.width, ROOM.height - DOOR.height, 0.24], [DOOR.x, (ROOM.height + DOOR.height) / 2, halfD], material.wall);
  block(staticRoom, [DOOR.width, DOOR.height, 0.08], [DOOR.x, DOOR.height / 2, DOOR.z], material.metal);
  block(staticRoom, [0.08, 0.08, 0.14], [DOOR.x - 0.45, 1.05, DOOR.z - 0.1], material.ink);
  const tiles = [];
  for (let x = -halfW + FLOOR.tile / 2; x < halfW; x += FLOOR.tile)
    for (let z = -halfD + FLOOR.tile / 2; z < halfD; z += FLOOR.tile)
      tiles.push({ position: [x, -FLOOR.thickness / 2, z], scale: [FLOOR.tile - FLOOR.seam, FLOOR.thickness, FLOOR.tile - FLOOR.seam] });
  instance(unitBox, material.floor, tiles);
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
    const mat = track(new THREE.MeshBasicMaterial({ map: texture, toneMapped: false }));
    const mesh = new THREE.Mesh(track(new THREE.PlaneGeometry(width, height)), mat);
    mesh.position.set(...position); mesh.rotation.y = rotation; parent.add(mesh);
    return { canvas: surface, texture, mesh, signature: '' };
  }
  const boards = BOARDS.map(config => {
    const group = new THREE.Group(); group.position.set(config.x, 0, config.z); group.rotation.y = config.yaw;
    staticRoom.add(group);
    block(group, [BOARD.width + 0.1, BOARD.top, 0.18], [0, BOARD.top / 2, -0.11], material.metal);
    const desk = block(group, [BOARD.width, 0.12, BOARD.deskDepth], [0, BOARD.deskY, BOARD.deskDepth / 2], material.steel);
    desk.rotation.x = BOARD.slope;
    for (const x of [-1.8, 1.8]) block(group, [0.12, 0.85, 0.65], [x, 0.425, 0.4], material.metal);
    block(group, [BOARD.width, BOARD.top - BOARD.bottom, 0.03], [0, (BOARD.top + BOARD.bottom) / 2, -0.015], material.steel);
    const face = paintedFace(BOARD.width, BOARD.top - BOARD.bottom, group, [0, (BOARD.top + BOARD.bottom) / 2, 0.031], 0, BOARD_PX.width, BOARD_PX.height);
    Object.assign(face.mesh.material, { transparent: true, depthWrite: false });
    face.mesh.renderOrder = 1;
    const layout = boardLayout(config.points.length, config.view);
    const windows = layout.windows.map(w => {
      const mat = track(createMaterial(THREE, theme, 'lamp', 'lampOff'));
      const mesh = block(group, [w.w / BOARD_PX.width * BOARD.width, w.h / BOARD_PX.height * (BOARD.top - BOARD.bottom), 0.022],
        [(w.x + w.w / 2) / BOARD_PX.width * BOARD.width - BOARD.width / 2,
          BOARD.top - (w.y + w.h / 2) / BOARD_PX.height * (BOARD.top - BOARD.bottom), 0.014], mat);
      mesh.userData.animated = true;
      mesh.receiveShadow = false;
      return mesh;
    });
    const labels = paintedFace(BOARD.width, 0.16, group, [0, 0.88, 0.81], 0, 1600, 80);
    return { ...face, config, labels, windows };
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
      screens.push({ ...paintedFace(0.85, 0.52, staticRoom, [desk.x + offset, 1.18, desk.z - 0.073]), lastPaint: -Infinity });
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
    { text: 'SHIFT SUPERVISOR', face: paintedFace(1.6, 0.18, staticRoom, [0, 0.62, 5.06], 0, 768, 112) },
  ];
  const plant = createPlantScene({ theme, reducedMotion, environment: environment.texture });
  const cctvTarget = track(new THREE.WebGLRenderTarget(480, 270, { type: THREE.HalfFloatType }));
  cctvTarget.texture.colorSpace = THREE.LinearSRGBColorSpace;
  const cctvMat = track(new THREE.MeshBasicMaterial({ map: cctvTarget.texture }));
  block(staticRoom, [0.12, CCTV.height + 0.16, CCTV.width + 0.16], [CCTV.x - 0.01, CCTV.y, CCTV.z], material.ink);
  const cctvScreen = new THREE.Mesh(track(new THREE.PlaneGeometry(CCTV.width, CCTV.height)), cctvMat);
  cctvScreen.rotation.y = Math.PI / 2; cctvScreen.position.set(CCTV.x + 0.06, CCTV.y, CCTV.z); staticRoom.add(cctvScreen);
  mergeStatic(staticRoom, { add: track });

  // The ordered operator controls occupy the three sloped desks.
  const knobPoses = knobIds.map((id, i) => {
    const b = BOARDS[Math.min(2, Math.floor(i * 3 / knobIds.length))];
    const first = Math.ceil(BOARDS.indexOf(b) * knobIds.length / 3);
    const count = Math.ceil((BOARDS.indexOf(b) + 1) * knobIds.length / 3) - first;
    const x = ((i - first + 0.5) / count - 0.5) * (BOARD.width - 0.4);
    const p = boardPoint(b, x, BOARD.deskY + 0.075, 0.5);
    return { position: [p.x, p.y, p.z], yaw: b.yaw };
  });
  const knobBase = track(new THREE.CylinderGeometry(0.11, 0.12, 0.025, 16));
  instance(knobBase, material.ink, knobPoses.map(p => ({ ...p, rotation: [0, p.yaw, 0] })));
  const knobBodies = instance(track(new THREE.CylinderGeometry(0.075, 0.085, 0.07, 16)), material.metal, knobPoses);
  const knobMarks = instance(unitBox, material.ink, knobPoses);
  const knobLevers = instance(unitBox, material.ink, knobPoses);
  const capGeometry = track(new THREE.CylinderGeometry(0.065, 0.075, 0.05, 16));
  const knobCaps = instance(capGeometry, material.accent, knobPoses);
  const litCaps = instance(capGeometry, material.lamp, knobPoses);

  let palette = theme, view = null, text = null, knobStates = [];
  let pose = { ...STANDING_SPOTS[DEFAULT_VIEW] }, selected = DEFAULT_VIEW, glide = null;
  const shown = new Map(), keys = new Set(), renderTimes = [], frameTimes = [];
  let disposed = false, visible = true, raf = 0, timer = 0, last = 0, lastCctv = -Infinity;
  let lastPlant = 0, plantDirty = true, plantMoving = false, themeDirty = true;
  let dragging = false, dragDistance = 0, pointerX = 0, pointerY = 0;
  const isPlant = () => selected === 'reactor' || selected === 'turbine';

  function applyTheme(next) {
    palette = next;
    scene.background = new THREE.Color(palette.sunken);
    lighting.setTheme(palette);
    Object.values(material).forEach(mat => applyMaterialPalette(mat, palette));
    material.light.emissive.set(palette.lightKey);
    setIndicator(material.lamp, palette, { lit: true });
    plant.setTheme(next); meters.setTheme(next); themeDirty = true; plantDirty = true;
    boards.forEach(b => { b.signature = ''; }); screens.forEach(s => { s.signature = ''; });
    for (const sign of signs) paintSign(sign.face, sign.text);
    boards.forEach((b, index) => {
      const ctx = b.labels.canvas.getContext('2d'); ctx.fillStyle = palette.surface; ctx.fillRect(0, 0, 1600, 80);
      const first = Math.ceil(index * knobIds.length / 3), end = Math.ceil((index + 1) * knobIds.length / 3);
      for (let i = first; i < end; i++) paintText(ctx, knobLabels[i], { x: (i - first) * 1600 / (end - first), y: 0, w: 1600 / (end - first), h: 80, font: 24 }, palette.ink);
      b.labels.texture.needsUpdate = true;
    });
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
    if (!isPlant()) pose = walk(pose, delta.x, delta.z, COLLISIONS, ROOM.radius);
    const walking = pose.x !== previous.x || pose.z !== previous.z;
    camera.position.set(pose.x, ROOM.eye, pose.z); camera.rotation.set(pose.pitch, pose.yaw, 0, 'YXZ');
    const needlesMoving = !isPlant() && easeNeedles(dt);
    if (!isPlant()) { meters.update(view?.pairs ?? [], shown); paintBoards(now); paintScreens(now); }
    placeKnobs();
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
    render(isPlant() ? plant.scene : scene, isPlant() ? plant.camera : camera);
    // The budget includes the containment pass: under 150 calls and 300,000 triangles.
    frameTimes.push(performance.now() - frameStart); if (frameTimes.length > 30) frameTimes.shift();
    const mean = frameTimes.reduce((a, b) => a + b, 0) / frameTimes.length;
    if (pixelRatio > 1 && frameTimes.length === 30 && mean > 20) { pixelRatio = 1; renderer.setPixelRatio(pixelRatio); resize(); }
    const flashing = !reducedMotion() && view?.alarms.some(a => a.state === 'active');
    if (glide || walking || needlesMoving || (isPlant() && plantMoving) || (!isPlant() && flashing)) {
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
    for (const board of boards) {
      const layout = boardLayout(board.config.points.length, board.config.view);
      const states = layout.windows.map(w => windowState(view?.alarms.find(a => a.key === w.key)?.state, now, reducedMotion()));
      const signature = JSON.stringify([text?.plantTime, text?.telemetry, states]);
      if (signature === board.signature && !themeDirty) continue;
      board.signature = signature;
      const ctx = board.canvas.getContext('2d');
      ctx.clearRect(0, 0, BOARD_PX.width, BOARD_PX.height);
      ctx.fillStyle = palette.surface; ctx.fillRect(0, 0, BOARD_PX.width, layout.header.h);
      paintText(ctx, board.config.title, layout.text.title, palette.ink, 'left');
      paintText(ctx, text ? `Plant time ${text.plantTime}` : 'Waiting for snapshot', layout.text.time, palette.text, 'right');
      paintText(ctx, text?.telemetry ?? 'No telemetry received', layout.text.telemetry, palette.text, 'left');
      layout.windows.forEach((w, i) => {
        const state = states[i];
        setIndicator(board.windows[i].material, palette, state);
        ctx.strokeStyle = palette.ink; ctx.lineWidth = 2;
        ctx.strokeRect(w.x - 2, w.y - 2, w.w + 4, w.h + 4);
        ctx.strokeStyle = state.lit ? palette.lampInk : palette.lampLegend;
        ctx.strokeRect(w.x + 1, w.y + 1, w.w - 2, w.h - 2);
        const lines = wrapLines(ctx, w.legend, w.w - 20, w.font);
        lines.forEach((line, j) => paintText(ctx, line, { x: w.x + 10, y: w.y + j * 23, w: w.w - 20, h: 23, font: w.font }, state.lit ? palette.lampInk : palette.lampLegend));
        if (state.mark) { ctx.fillStyle = palette.lampInk; ctx.fillRect(w.x + w.w - 9, w.y + 3, 6, 6); }
      });
      board.texture.needsUpdate = true;
    }
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
  function placeKnobs() {
    const meshes = [knobBodies, knobMarks, knobLevers, knobCaps, litCaps];
    knobPoses.forEach((p, i) => {
      const state = knobStates[i] ?? { kind: 'switch', travel: 0 };
      const dial = state.kind === 'dial' || state.kind === 'rotary';
      for (let part = 0; part < meshes.length; part++) {
        const lit = knobIds[i] === 'manual-trip' ? view?.reportedStatus.reactorTripped
          : knobIds[i] === 'acknowledge' && view?.alarms.some(a => a.state === 'active');
        const on = part < 2 ? dial : part === 2 ? state.kind === 'switch'
          : state.kind === 'button' && (part === 4 ? lit : !lit);
        dummy.position.set(...p.position); dummy.position.y += part === 1 ? 0.075 : 0.045;
        dummy.rotation.set(0, p.yaw, 0); dummy.scale.setScalar(on ? 1 : 0);
        if (part === 1 && on) { dummy.scale.set(0.014, 0.008, 0.065); dummy.rotation.y += Math.PI - ((state.fraction ?? 0) - 0.5) * NEEDLE_SWEEP; }
        if (part === 2 && on) { dummy.scale.set(0.035, 0.12, 0.035); dummy.rotation.x = ((state.travel ?? 0) * 2 - 1) * -0.42; }
        if (part >= 3) dummy.position.y -= (state.depth ?? 0) * 0.02;
        dummy.updateMatrix(); meshes[part].setMatrixAt(i, dummy.matrix);
      }
    });
    meshes.forEach(m => { m.instanceMatrix.needsUpdate = true; m.computeBoundingSphere(); });
  }
  function paintText(ctx, value, box, color, align = 'center') {
    ctx.textAlign = align;
    ctx.textBaseline = 'middle';
    ctx.fillStyle = color;
    ctx.font = `600 ${box.font}px ${FONT}`;
    const x = align === 'left' ? box.x : align === 'right' ? box.x + box.w : box.x + box.w / 2;
    ctx.fillText(value, x, box.y + box.h / 2);
  }

  function setView(name) {
    if (!(name in STANDING_SPOTS) && name !== 'reactor' && name !== 'turbine') return;
    selected = name; keys.clear(); dragging = false;
    if (document.pointerLockElement === canvas) document.exitPointerLock();
    if (isPlant()) { glide = null; plant.setView(name); }
    else {
      const end = STANDING_SPOTS[name], path = walkPath(pose, end, COLLISIONS, ROOM.radius);
      if (reducedMotion()) { pose = { ...end }; glide = null; }
      else if (path && (Math.hypot(pose.x - end.x, pose.z - end.z) > 0.001 || Math.abs(pose.yaw - end.yaw) > 0.001 || Math.abs(pose.pitch - end.pitch) > 0.001))
        glide = { start: { ...pose }, end, path, at: performance.now() };
    }
    const label = STANDING_SPOTS[name]?.name ?? (name === 'reactor' ? 'Reactor building' : 'Turbine hall');
    container.dataset.view = label;
    canvas.setAttribute('aria-label', `${label}. First-person control room and plant views. The text section lists the same values.`);
    requestFrame();
  }
  const walkingKeys = new Set(['KeyW', 'KeyA', 'KeyS', 'KeyD', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight']);
  listen(canvas, 'keydown', event => {
    if (document.activeElement !== canvas || isPlant() || !walkingKeys.has(event.code) || event.ctrlKey || event.metaKey || event.altKey) return;
    event.preventDefault(); keys.add(event.code); glide = null; requestFrame();
  });
  listen(canvas, 'keyup', event => { if (keys.delete(event.code)) { event.preventDefault(); requestFrame(); } });
  const stop = () => { keys.clear(); dragging = false; requestFrame(); };
  listen(canvas, 'blur', stop); listen(window, 'blur', stop);
  listen(document, 'pointerlockchange', () => { if (document.pointerLockElement !== canvas) stop(); });
  listen(canvas, 'pointerdown', event => {
    if (event.button !== 0 || isPlant()) return;
    canvas.focus(); dragging = true; dragDistance = 0; pointerX = event.clientX; pointerY = event.clientY;
    canvas.setPointerCapture?.(event.pointerId); glide = null;
  });
  listen(document, 'pointermove', event => {
    const locked = document.pointerLockElement === canvas;
    if ((!dragging && !locked) || isPlant()) return;
    const dx = locked ? event.movementX : event.clientX - pointerX, dy = locked ? event.movementY : event.clientY - pointerY;
    pointerX = event.clientX; pointerY = event.clientY; dragDistance += Math.abs(dx) + Math.abs(dy);
    pose = look(pose, dx, dy); requestFrame();
  });
  listen(canvas, 'pointerup', event => {
    if (!dragging) return;
    dragging = false;
    if (canvas.hasPointerCapture?.(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
    if (dragDistance < 4 && document.pointerLockElement !== canvas) {
      try { canvas.requestPointerLock?.()?.catch?.(() => {}); } catch { /* Drag look remains available. */ }
    }
    requestFrame();
  });
  listen(canvas, 'pointercancel', stop);
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
