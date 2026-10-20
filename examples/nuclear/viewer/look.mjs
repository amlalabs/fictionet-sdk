import { ROOM, BOARD, BOARDS, DESKS, CEILING_LIGHTS } from './board-layout.mjs';

// Three is supplied by the stage so the material specs can also run in Node.
export const MATERIAL_ROLES = Object.freeze({
  paintedSteel: Object.freeze({ roughness: 0.72, metalness: 0.18 }),
  brushedMetal: Object.freeze({ roughness: 0.32, metalness: 0.8 }),
  glass: Object.freeze({ roughness: 0.12, metalness: 0 }),
  rubber: Object.freeze({ roughness: 0.96, metalness: 0 }),
  concrete: Object.freeze({ roughness: 0.92, metalness: 0 }),
  lamp: Object.freeze({ roughness: 0.28, metalness: 0 }),
});

export function materialSpec(palette, role, token) {
  const surface = MATERIAL_ROLES[role];
  if (!surface) throw new RangeError(`Unknown material role: ${role}`);
  if (!palette[token]) throw new RangeError(`Missing palette color: ${token}`);
  return { ...surface, color: palette[token] };
}

export function createMaterial(THREE, palette, role, token, options = {}) {
  const material = new THREE.MeshStandardMaterial({ ...materialSpec(palette, role, token), ...options });
  material.userData.paletteToken = token;
  return material;
}

export function applyMaterialPalette(material, palette) {
  material.color.set(palette[material.userData.paletteToken]);
}

export function createDisplayMaterial(THREE, palette, texture) {
  const material = createMaterial(THREE, palette, 'lamp', 'lightKey', {
    map: texture,
    emissiveMap: texture,
    emissiveIntensity: 1,
    toneMapped: false,
    roughness: 1,
    metalness: 0,
    envMapIntensity: 0,
  });
  // Neutral multipliers preserve the canvas palette without reflected light.
  material.color.setScalar(0);
  material.emissive.setScalar(1);
  material.onBeforeCompile = (shader) => {
    shader.fragmentShader = shader.fragmentShader.replace(
      '#include <opaque_fragment>',
      'outgoingLight = totalEmissiveRadiance;\n#include <opaque_fragment>',
    );
  };
  return material;
}

export function indicatorSpec(palette, { lit }) {
  return {
    color: lit ? palette.lampGlow : palette.lampOff,
    emissive: palette.lampGlow,
    emissiveIntensity: lit ? 2.4 : 0,
  };
}

export function setIndicator(material, palette, state) {
  const spec = indicatorSpec(palette, state);
  material.color.set(spec.color);
  material.emissive.set(spec.emissive);
  material.emissiveIntensity = spec.emissiveIntensity;
}

export function createRenderer(THREE) {
  const renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 0.95;
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  renderer.shadowMap.autoUpdate = false;
  renderer.shadowMap.needsUpdate = true;
  renderer.info.autoReset = false;
  return renderer;
}

export function createEnvironment(THREE, renderer, palette) {
  const room = new THREE.Scene();
  const box = new THREE.BoxGeometry(10, 6, 10);
  const panel = new THREE.PlaneGeometry(1, 1);
  const walls = new THREE.MeshBasicMaterial({ color: palette.lightGround, side: THREE.BackSide });
  const glow = createMaterial(THREE, palette, 'lamp', 'lightKey', {
    emissive: palette.lightKey,
    emissiveIntensity: 5,
    side: THREE.DoubleSide,
  });
  room.add(new THREE.Mesh(box, walls));
  for (const [position, rotation, scale] of [
    [
      [-2.5, 2.9, 0],
      [Math.PI / 2, 0, 0],
      [1.5, 4, 1],
    ],
    [
      [2.5, 2.9, 0],
      [Math.PI / 2, 0, 0],
      [1.5, 4, 1],
    ],
    [
      [0, 1, -4.9],
      [0, 0, 0],
      [4, 1.5, 1],
    ],
  ]) {
    const mesh = new THREE.Mesh(panel, glow);
    mesh.position.set(...position);
    mesh.rotation.set(...rotation);
    mesh.scale.set(...scale);
    room.add(mesh);
  }
  const pmrem = new THREE.PMREMGenerator(renderer);
  try {
    return pmrem.fromScene(room, 0.04, 0.1, 30, { size: 128 });
  } finally {
    pmrem.dispose();
    box.dispose();
    panel.dispose();
    walls.dispose();
    glow.dispose();
    room.clear();
  }
}

export function createLighting(THREE, scene, palette, plant = false) {
  const fill = new THREE.HemisphereLight(palette.lightKey, palette.lightGround, plant ? 0.35 : 1.1);
  const key = new THREE.DirectionalLight(palette[plant ? 'plantKey' : 'lightKey'], plant ? 1.25 : 1.5);
  key.position.set(...(plant ? [-6, 14, 18] : [-3, 3.4, 3]));
  key.target.position.set(...(plant ? [0, 0, 0] : [0, 0, -1.5]));
  key.castShadow = plant;
  key.shadow.mapSize.set(1024, 1024);
  const extent = plant ? 19 : 8;
  Object.assign(key.shadow.camera, {
    left: -extent,
    right: extent,
    top: extent,
    bottom: -extent,
    near: 0.1,
    far: plant ? 65 : 22,
  });
  key.shadow.camera.updateProjectionMatrix();
  key.shadow.normalBias = 0.025;
  key.shadow.bias = -0.00015;
  scene.add(fill, key, key.target);
  scene.environmentIntensity = plant ? 0.22 : 0.45;
  return {
    setTheme(next) {
      fill.color.set(next[plant ? 'plantKey' : 'lightKey']);
      fill.groundColor.set(next.lightGround);
      key.color.set(next[plant ? 'plantKey' : 'lightKey']);
    },
    dispose() {
      key.dispose();
      fill.dispose();
      scene.remove(key, fill, key.target);
    },
  };
}

// Scalar irradiance modulates the palette; it introduces no new surface colors.
export function roomLightAt(point, normal) {
  let pool = 0;
  for (const x of CEILING_LIGHTS.xs)
    for (const z of CEILING_LIGHTS.zs) {
      const distance = (point.x - x) ** 2 + (point.z - z) ** 2;
      pool = Math.max(pool, Math.exp(-distance / 2.2));
    }
  let light = 0.62 + 0.38 * pool;
  const wallGap = Math.min(ROOM.width / 2 - Math.abs(point.x), ROOM.depth / 2 - Math.abs(point.z));
  light *= 0.76 + 0.24 * Math.min(1, Math.max(0, wallGap) / 0.65);
  if (normal.y < -0.5) light *= 0.65;
  for (const desk of DESKS) {
    const beneath = Math.abs(point.x - desk.x) < desk.w / 2 && Math.abs(point.z - desk.z) < desk.d / 2;
    if (beneath && point.y < 0.76) light *= 0.62;
  }
  for (const board of BOARDS) {
    const dx = point.x - board.x;
    const dz = point.z - board.z;
    const across = Math.cos(board.yaw) * dx - Math.sin(board.yaw) * dz;
    const front = Math.sin(board.yaw) * dx + Math.cos(board.yaw) * dz;
    if (Math.abs(across) > BOARD.width / 2 || front < -0.25 || front > BOARD.deskDepth + 0.25) continue;
    if (point.y < BOARD.deskY - 0.08) light *= 0.64;
    if (point.y < 0.12) light *= 0.8;
  }
  return Math.max(0.2, light);
}

export function bakeRoomGeometry(THREE, mesh) {
  const positions = mesh.geometry.attributes.position;
  const normals = mesh.geometry.attributes.normal;
  const colors = new Float32Array(positions.count * 3);
  const point = new THREE.Vector3();
  const normal = new THREE.Vector3();
  mesh.updateWorldMatrix(true, false);
  const normalMatrix = new THREE.Matrix3().getNormalMatrix(mesh.matrixWorld);
  for (let i = 0; i < positions.count; i++) {
    point.fromBufferAttribute(positions, i).applyMatrix4(mesh.matrixWorld);
    normal.fromBufferAttribute(normals, i).applyMatrix3(normalMatrix).normalize();
    const light = roomLightAt(point, normal);
    colors.set([light, light, light], i * 3);
  }
  mesh.geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
  mesh.material.vertexColors = true;
}

/**
 * Joins indexed geometries into one, each moved by its matrix. Normals move
 * with the matrix; the UVs are copied as they are.
 */
export function joinGeometries(THREE, entries, track) {
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
