import { BOARD, BOARD_PX, BOARDS, boardLayout, boardPoint, cellLayout } from './board-layout.mjs';
import { formatGap, formatValue } from './instruments.mjs';
import { createMaterial, applyMaterialPalette, joinGeometries } from './look.mjs';

const TAU = Math.PI * 2;
const FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif";

// The reserved height measures the ink, including descenders, rather than the font em.
export function paintLetters(ctx, value, box, color, align = 'center') {
  ctx.save();
  ctx.fillStyle = color;
  ctx.textAlign = align;
  ctx.textBaseline = 'alphabetic';
  ctx.font = `600 ${box.font}px ${FONT}`;
  const metrics = ctx.measureText(value || 'M');
  const ascent = metrics.actualBoundingBoxAscent ?? box.font * 0.8;
  const descent = metrics.actualBoundingBoxDescent ?? box.font * 0.2;
  const inkHeight = ascent + descent || box.font;
  const stretch = Math.min(box.stretch ?? 1, box.w / (metrics.width || box.w));
  let x = box.x + box.w / 2;
  if (align === 'left') x = box.x;
  if (align === 'right') x = box.x + box.w;
  ctx.translate(x, box.y + box.h / 2);
  ctx.scale(stretch, box.font / inkHeight);
  ctx.fillText(value, 0, (ascent - descent) / 2);
  ctx.restore();
}

// Angles are measured from the right in the meter's local plane.
export function needleAngle(value, [low, high]) {
  if (value === null || value === undefined) return null;
  return -Math.PI * 0.75 - Math.PI * 1.5 * Math.max(0, Math.min(1, (value - low) / (high - low)));
}

export function scaleTicks(range) {
  const span = range[1] - range[0];
  let intervals = 4;
  while (intervals > 1 && !Number.isInteger(span / intervals)) intervals--;
  return Array.from({ length: intervals * 2 + 1 }, (_, i) => {
    const value = range[0] + (span * i) / (intervals * 2);
    return { value, angle: needleAngle(value, range), label: i % 2 ? '' : String(value) };
  });
}

export function heldTag(sampledAtMs) {
  if (sampledAtMs === null || sampledAtMs === undefined) return 'HELD';
  const tenths = Math.floor(sampledAtMs / 100);
  return `HELD ${Math.floor(tenths / 600)}:${(Math.floor(tenths / 10) % 60).toString().padStart(2, '0')}.${tenths % 10}`;
}

// One atlas for scales and plates, one for snapshot readouts. Neither uses eased values.
export function createMeters(
  THREE,
  scene,
  theme,
  { makeCanvas = () => document.createElement('canvas'), anisotropy = 1 } = {},
) {
  const resources = new Set();
  const track = (resource) => {
    resources.add(resource);
    return resource;
  };
  const group = new THREE.Group();
  scene.add(group);
  const dummy = new THREE.Object3D();
  const unitBox = track(new THREE.BoxGeometry(1, 1, 1));
  const circle = track(new THREE.CircleGeometry(1, 24));
  const hub = track(new THREE.CircleGeometry(1, 8));
  const plane = track(new THREE.PlaneGeometry(1, 1));
  const ring = track(new THREE.RingGeometry(0.85, 1, 24));
  const inlay = track(new THREE.RingGeometry(0.92, 0.95, 24));
  const dash = track(new THREE.RingGeometry(0.87, 0.99, 3, 1, 0, TAU / 24));
  const wall = track(new THREE.CylinderGeometry(1, 1, 1, 24, 1, true).rotateX(Math.PI / 2));
  const housing = joinGeometries(
    THREE,
    [
      { geometry: ring, matrix: new THREE.Matrix4() },
      { geometry: wall, matrix: new THREE.Matrix4().makeTranslation(0, 0, -0.031 / 0.06) },
    ],
    { add: track },
  );
  const blade = track(new THREE.BoxGeometry(0.76, 0.045, 0.025).translate(0.28, 0, 0));
  const standard = (role, token) => track(createMaterial(THREE, theme, role, token));
  const flat = (token) => standard('paintedSteel', token);
  const materials = {
    black: standard('rubber', 'rubber'),
    metal: standard('brushedMetal', 'metal'),
    ink: flat('ink'),
    held: flat('lampLegend'),
    warning: flat('warning'),
    glass: track(
      new THREE.MeshPhysicalMaterial({
        color: theme.lightKey,
        roughness: 0.85,
        metalness: 0,
        clearcoat: 0,
        transparent: true,
        opacity: 0.045,
        depthWrite: false,
      }),
    ),
  };
  materials.glass.userData.paletteToken = 'lightKey';

  function atlas() {
    const canvas = makeCanvas();
    canvas.width = 2048;
    canvas.height = 1536;
    const texture = track(new THREE.CanvasTexture(canvas));
    texture.colorSpace = THREE.SRGBColorSpace;
    texture.anisotropy = anisotropy;
    const material = track(createMaterial(THREE, theme, 'paintedSteel', 'lightKey', { map: texture }));
    return { canvas, texture, material, positions: [], normals: [], uvs: [] };
  }
  const scales = atlas(),
    readouts = atlas();
  const parts = [];
  function instances(name, geometry, material, count) {
    const mesh = track(new THREE.InstancedMesh(geometry, material, count));
    mesh.name = name;
    // Moving or appearing instances must not retain an old, empty bounding sphere.
    mesh.frustumCulled = false;
    group.add(mesh);
    parts.push(mesh);
    return mesh;
  }
  const cells = BOARDS.flatMap((board) =>
    boardLayout(board.points.length, board.view).cells.map((cell, i) => ({
      board,
      cell,
      key: board.points[i],
      layout: cellLayout(cell.w, cell.h),
      scaleSignature: '',
      readoutSignature: '',
    })),
  );
  const count = cells.length;
  const blackRims = instances('HMI bezels', housing, materials.black, count);
  const metalRims = instances('PLANT bezels', housing, materials.metal, count);
  const inlays = instances('PLANT inlays', inlay, materials.ink, count);
  const plates = instances('Engraved plates', unitBox, materials.metal, count * 3);
  const needles = instances('Meter needles', blade, materials.ink, count * 2);
  const hubs = instances('Needle hubs', hub, materials.ink, count * 2);
  const glass = instances('Meter glass', circle, materials.glass, count * 2);
  glass.renderOrder = 2;
  const warnings = instances('Marked HMI rims', ring, materials.warning, count);
  const amberDashes = instances('Marked held rims', dash, materials.warning, count * 16);
  const heldDashes = instances('Held rims', dash, materials.held, count * 16);
  const links = instances('Marked links', unitBox, materials.warning, count);
  for (const mesh of [needles, warnings, amberDashes, heldDashes, links]) {
    mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    mesh.count = 0;
  }

  const pixel = BOARD.width / BOARD_PX.width;
  function transform(entry, x, y, z, sx, sy, sz = 1, angle = 0) {
    const p = boardPoint(
      entry.board,
      (entry.cell.x + x) * pixel - BOARD.width / 2,
      BOARD.top - (entry.cell.y + y) * pixel,
      z,
    );
    dummy.position.set(p.x, p.y, p.z);
    dummy.rotation.set(0, entry.board.yaw, angle, 'YXZ');
    dummy.scale.set(sx, sy, sz);
    dummy.updateMatrix();
    return dummy.matrix;
  }
  function atDial(mesh, index, entry, dial, z, scale = 1, angle = 0, depth) {
    const r = dial.radius * pixel;
    mesh.setMatrixAt(
      index,
      transform(entry, dial.x + dial.radius, dial.y + dial.radius, z, r * scale, r * scale, depth ?? r, angle),
    );
  }
  function atBox(mesh, index, entry, box, z, depth) {
    mesh.setMatrixAt(
      index,
      transform(entry, box.x + box.w / 2, box.y + box.h / 2, z, box.w * pixel, box.h * pixel, depth),
    );
  }
  function printGeometry(target, source, matrix, rect) {
    const geometry = source.toNonIndexed();
    geometry.applyMatrix4(matrix);
    target.positions.push(...geometry.attributes.position.array);
    target.normals.push(...geometry.attributes.normal.array);
    const uv = geometry.attributes.uv;
    for (let i = 0; i < uv.count; i++) {
      target.uvs.push(
        (rect.x + uv.getX(i) * rect.w) / target.canvas.width,
        1 - (rect.y + (1 - uv.getY(i)) * rect.h) / target.canvas.height,
      );
    }
    geometry.dispose();
  }
  function printBox(target, entry, box, rect, z) {
    printGeometry(
      target,
      plane,
      transform(entry, box.x + box.w / 2, box.y + box.h / 2, z, box.w * pixel, box.h * pixel),
      rect,
    );
  }
  cells.forEach((entry, index) => {
    const { dials, text, gapLine } = entry.layout;
    const x = (index % 4) * 512,
      y = Math.floor(index / 4) * 256;
    entry.face = { x, y, w: 256, h: 256 };
    entry.labelBoxes = [text.label, text.hmi, text.plant];
    entry.labels = entry.labelBoxes.map((box, i) => {
      const rect = { x: x + 256, y: y + i * 64, w: 256, h: 64 };
      atBox(plates, index * 3 + i, entry, box, 0.045, 0.025);
      printBox(scales, entry, box, rect, 0.058);
      return rect;
    });
    entry.readoutBoxes = [text.reported, text.truth, gapLine, text.held];
    entry.readings = entry.readoutBoxes.map((box, i) => {
      const rect = { x, y: y + i * 64, w: 512, h: 64 };
      printBox(readouts, entry, box, rect, 0.04);
      return rect;
    });
    dials.forEach((dial, i) => {
      atDial(i ? metalRims : blackRims, index, entry, dial, 0.086, 1, 0, 0.06);
      if (i) atDial(inlays, index, entry, dial, 0.087);
      atDial(hubs, index * 2 + i, entry, dial, 0.084, 0.085);
      atDial(glass, index * 2 + i, entry, dial, 0.091, 0.845);
      const r = dial.radius * pixel * 0.85;
      printGeometry(
        scales,
        circle,
        transform(entry, dial.x + dial.radius, dial.y + dial.radius, 0.072, r, r),
        entry.face,
      );
    });
  });
  for (const target of [scales, readouts]) {
    const geometry = track(new THREE.BufferGeometry());
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(target.positions, 3));
    geometry.setAttribute('normal', new THREE.Float32BufferAttribute(target.normals, 3));
    geometry.setAttribute('uv', new THREE.Float32BufferAttribute(target.uvs, 2));
    const mesh = new THREE.Mesh(geometry, target.material);
    mesh.name = target === scales ? 'Printed scales and plates' : 'Snapshot readouts';
    group.add(mesh);
    delete target.positions;
    delete target.normals;
    delete target.uvs;
  }
  parts.forEach((mesh) => {
    mesh.instanceMatrix.needsUpdate = true;
  });
  let palette = theme;

  function lettering(ctx, value, rect, box, foreground, background) {
    ctx.save();
    ctx.translate(rect.x, rect.y);
    ctx.scale(rect.w / box.w, rect.h / box.h);
    ctx.fillStyle = background;
    ctx.fillRect(0, 0, box.w, box.h);
    paintLetters(ctx, value, { ...box, x: 0, y: 0 }, foreground);
    ctx.restore();
  }
  function paintScale(entry, pair) {
    const signature = JSON.stringify([pair.label, pair.range, pair.unit]);
    if (entry.scaleSignature === signature) return;
    entry.scaleSignature = signature;
    const ctx = scales.canvas.getContext('2d');
    const { x, y } = entry.face;
    ctx.fillStyle = palette.surface;
    ctx.fillRect(x, y, 256, 256);
    ctx.strokeStyle = palette.ink;
    ctx.fillStyle = palette.ink;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.font = `600 23px ${FONT}`;
    for (const tick of scaleTicks(pair.range)) {
      const c = Math.cos(tick.angle),
        s = -Math.sin(tick.angle);
      ctx.lineWidth = tick.label ? 3 : 2;
      ctx.beginPath();
      ctx.moveTo(x + 128 + c * (tick.label ? 99 : 107), y + 128 + s * (tick.label ? 99 : 107));
      ctx.lineTo(x + 128 + c * 118, y + 128 + s * 118);
      ctx.stroke();
      if (tick.label) ctx.fillText(tick.label, x + 128 + c * 77, y + 128 + s * 77);
    }
    ctx.font = `600 26px ${FONT}`;
    ctx.fillText(pair.unit === 'C' ? '°C' : pair.unit, x + 128, y + 178);
    for (const [i, label] of [pair.label.replace('Steam generator', 'Steam gen.'), 'HMI', 'PLANT'].entries()) {
      const box = entry.labels[i];
      lettering(ctx, label, box, entry.labelBoxes[i], palette.ink, palette.steel);
      ctx.strokeStyle = palette.strongLine;
      ctx.lineWidth = 2;
      ctx.strokeRect(box.x + 2, box.y + 2, box.w - 4, box.h - 4);
    }
    scales.texture.needsUpdate = true;
  }
  function paintReadout(entry, pair) {
    const marked = pair.reported !== null && pair.marked;
    let gap = '';
    if (pair.reported === null) {
      gap = 'No reading';
    } else if (marked) {
      gap = `▲ Gap ${formatGap(pair.gap, pair.unit)}`;
    }
    const values = [
      formatValue(pair.reported, pair.unit),
      formatValue(pair.trueValue, pair.unit),
      gap,
      pair.frozen ? heldTag(pair.sampledAtMs) : '',
    ];
    const signature = JSON.stringify([values, marked]);
    if (entry.readoutSignature === signature) return;
    entry.readoutSignature = signature;
    const ctx = readouts.canvas.getContext('2d');
    values.forEach((value, i) =>
      lettering(
        ctx,
        value,
        entry.readings[i],
        entry.readoutBoxes[i],
        i === 2 && marked ? palette.surface : palette.ink,
        i === 2 && marked ? palette.warning : palette.steel,
      ),
    );
    readouts.texture.needsUpdate = true;
  }
  return {
    setTheme(next) {
      palette = next;
      Object.values(materials).forEach((mat) => applyMaterialPalette(mat, palette));
      cells.forEach((entry) => {
        entry.scaleSignature = '';
        entry.readoutSignature = '';
      });
    },
    update(pairs, shown) {
      for (const mesh of [needles, warnings, amberDashes, heldDashes, links]) mesh.count = 0;
      for (const entry of cells) {
        const pair = pairs.find((p) => p.key === entry.key);
        if (!pair) continue;
        paintScale(entry, pair);
        paintReadout(entry, pair);
        const level = shown.get(pair.key);
        entry.layout.dials.forEach((dial, i) => {
          let value = level?.truth ?? pair.trueValue;
          if (!i) value = pair.reported === null ? null : (level?.reported ?? pair.reported);
          const angle = needleAngle(value, pair.range);
          if (angle !== null) atDial(needles, needles.count++, entry, dial, 0.081, 1, angle);
        });
        const [left, right] = entry.layout.dials;
        if (pair.frozen) {
          const mesh = pair.marked ? amberDashes : heldDashes;
          for (let i = 0; i < 16; i++) atDial(mesh, mesh.count++, entry, left, 0.088, 1, (i * TAU) / 16);
        } else if (pair.marked) atDial(warnings, warnings.count++, entry, left, 0.088);
        if (pair.marked) {
          const bar = { x: left.x + left.w, y: left.y + left.radius - 3, w: right.x - left.x - left.w, h: 6 };
          atBox(links, links.count++, entry, bar, 0.06, 0.015);
        }
      }
      for (const mesh of [needles, warnings, amberDashes, heldDashes, links]) {
        mesh.visible = mesh.count > 0;
        mesh.instanceMatrix.needsUpdate = true;
      }
    },
    dispose() {
      group.removeFromParent();
      resources.forEach((resource) => resource.dispose());
      group.clear();
      resources.clear();
    },
  };
}
