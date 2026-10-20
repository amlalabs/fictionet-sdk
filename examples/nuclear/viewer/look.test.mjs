import test from 'node:test';
import assert from 'node:assert/strict';
import { MATERIAL_ROLES, materialSpec, indicatorSpec, setIndicator, createRenderer, createMaterial,
  applyMaterialPalette, roomLightAt } from './look.mjs';
import { windowState, DESKS, BOARDS, boardPoint, CEILING_LIGHTS } from './board-layout.mjs';

test('surface roles separate painted steel, brushed metal, glass, rubber and concrete', () => {
  for (const spec of Object.values(MATERIAL_ROLES)) {
    assert.ok(spec.roughness >= 0 && spec.roughness <= 1);
    assert.ok(spec.metalness >= 0 && spec.metalness <= 1);
    assert.ok(Object.isFrozen(spec));
  }
  const { paintedSteel, brushedMetal, glass, rubber, concrete } = MATERIAL_ROLES;
  assert.ok(brushedMetal.metalness > paintedSteel.metalness);
  assert.ok(paintedSteel.roughness > brushedMetal.roughness);
  assert.ok(brushedMetal.roughness > glass.roughness);
  assert.ok(rubber.roughness > paintedSteel.roughness);
  assert.ok(concrete.roughness > paintedSteel.roughness);
  for (const spec of [glass, rubber, concrete]) assert.equal(spec.metalness, 0);
});

test('material specs require a palette color and leave the palette and roles intact', () => {
  const palette = Object.freeze({ steel: '#acb5a8', metal: '#8a9482' });
  for (const role of Object.keys(MATERIAL_ROLES)) {
    assert.deepEqual(materialSpec(palette, role, 'steel'), { ...MATERIAL_ROLES[role], color: palette.steel });
    const spec = materialSpec(palette, role, 'metal');
    spec.roughness = -1;
    assert.ok(materialSpec(palette, role, 'metal').roughness >= 0);
  }
  assert.throws(() => materialSpec(palette, 'missing', 'steel'), RangeError);
  assert.throws(() => materialSpec(palette, 'glass', 'missing'), RangeError);
});

const palette = Object.freeze({ lampGlow: '#ffbe50', lampOff: '#222b27' });
const color = () => ({ value: null, set(value) { this.value = value; } });

test('emission follows the window decision through flashing, acknowledgement and clearing', () => {
  const material = { color: color(), emissive: color(), emissiveIntensity: 0 };
  for (const reduced of [false, true]) {
    for (const state of [undefined, 'normal', 'active', 'acknowledged']) {
      for (const time of [0, 249, 250, 499, 500, 749, 750, 999, 1000]) {
        const decision = windowState(state, time, reduced);
        const spec = indicatorSpec(palette, decision);
        setIndicator(material, palette, decision);
        assert.equal(material.emissiveIntensity > 1, decision.lit);
        assert.equal(material.emissiveIntensity, spec.emissiveIntensity);
        assert.equal(material.color.value, decision.lit ? palette.lampGlow : palette.lampOff);
        assert.equal(material.emissive.value, palette.lampGlow);
        if (!decision.lit) assert.equal(material.emissiveIntensity, 0);
      }
    }
  }
  setIndicator(material, palette, windowState('acknowledged', 250));
  assert.ok(material.emissiveIntensity > 1);
  setIndicator(material, palette, windowState('normal', 250));
  assert.equal(material.emissiveIntensity, 0);
});

test('material creation and theme updates use the requested role and token', () => {
  class Material {
    constructor(spec) { this.spec = spec; this.userData = {}; this.color = color(); }
  }
  const material = createMaterial({ MeshStandardMaterial: Material }, palette, 'lamp', 'lampOff', { depthWrite: false });
  assert.equal(material.spec.roughness, MATERIAL_ROLES.lamp.roughness);
  assert.equal(material.spec.color, palette.lampOff);
  assert.equal(material.spec.depthWrite, false);
  const next = { lampOff: '#27312a' };
  applyMaterialPalette(material, next);
  assert.equal(material.color.value, next.lampOff);
});

test('the renderer factory creates one context with filmic output and shadow accounting', () => {
  let count = 0;
  const THREE = {
    ACESFilmicToneMapping: Symbol(), SRGBColorSpace: Symbol(), PCFSoftShadowMap: Symbol(),
    WebGLRenderer: class {
      constructor(options) { count++; this.options = options; this.shadowMap = {}; this.info = {}; }
    },
  };
  const renderer = createRenderer(THREE);
  assert.equal(count, 1);
  assert.equal(renderer.options.antialias, true);
  assert.equal(renderer.toneMapping, THREE.ACESFilmicToneMapping);
  assert.ok(renderer.toneMappingExposure > 0 && renderer.toneMappingExposure <= 1.5);
  assert.equal(renderer.outputColorSpace, THREE.SRGBColorSpace);
  assert.equal(renderer.shadowMap.enabled, true);
  assert.equal(renderer.shadowMap.type, THREE.PCFSoftShadowMap);
  assert.equal(renderer.info.autoReset, false);
});

test('baked light pools under troffers and darkens kneeholes, desk lips, board bases and corners', () => {
  const up = { x: 0, y: 1, z: 0 };
  const down = { x: 0, y: -1, z: 0 };
  const x = CEILING_LIGHTS.xs[1];
  const z = CEILING_LIGHTS.zs[0];
  const underLight = roomLightAt({ x, y: 1.8, z }, up);
  const betweenLights = roomLightAt({ x: 0, y: 1.8, z: z + 1.5 }, up);
  assert.ok(underLight > betweenLights + 0.2);
  const desk = DESKS[0];
  const knee = { x: desk.x, y: 0.6, z: desk.z };
  const top = { ...knee, y: 0.82 };
  assert.ok(roomLightAt(knee, up) < roomLightAt(top, up) * 0.7);
  assert.ok(roomLightAt(knee, down) < roomLightAt(knee, up));
  const base = boardPoint(BOARDS[2], 0, 0.04, 0.4);
  assert.ok(roomLightAt(base, up) < roomLightAt({ ...base, y: 1.8 }, up) * 0.6);
  assert.ok(roomLightAt({ x: 6.9, y: 0, z: 6.9 }, up) < betweenLights);
});
