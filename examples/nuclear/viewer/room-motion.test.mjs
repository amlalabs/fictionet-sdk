import test from 'node:test';
import assert from 'node:assert/strict';
import { PITCH_LIMIT, look, wrapYaw, glideEase, circleHits, walk, walkDelta, walkPath, glidePose } from './room-motion.mjs';
import { ROOM, COLLISIONS, STANDING_SPOTS } from './board-layout.mjs';

test('look wraps yaw and limits pitch without moving the eye', () => {
  const p = look({ x: 2, z: 3, yaw: 0, pitch: 0 }, 10000, -10000);
  assert.equal(p.x, 2); assert.equal(p.z, 3);
  assert.equal(p.pitch, PITCH_LIMIT); assert.ok(Math.abs(p.yaw) <= Math.PI);
  assert.equal(look(p, 0, 10000).pitch, -PITCH_LIMIT);
  assert.ok(Math.abs(wrapYaw(10 * Math.PI)) < 1e-12);
});
test('circle collision handles sides, corners, tangency and an interior center', () => {
  const b = { minX: 0, maxX: 1, minZ: 0, maxZ: 1 };
  assert.equal(circleHits({ x: -0.2, z: 0.5 }, 0.22, b), true);
  assert.equal(circleHits({ x: -0.22, z: 0.5 }, 0.22, b), false);
  assert.equal(circleHits({ x: -0.2, z: -0.2 }, 0.22, b), false);
  assert.equal(circleHits({ x: -0.1, z: -0.1 }, 0.22, b), true);
  assert.equal(circleHits({ x: 0.5, z: 0.5 }, 0.22, b), true);
});
test('walking cannot tunnel through a thin wall and slides along it', () => {
  const b = { minX: 0, maxX: 0.1, minZ: -10, maxZ: 10 };
  const p = walk({ x: -1, z: 0 }, 8, 2, [b], 0.22);
  assert.ok(p.x <= -0.22); assert.ok(Math.abs(p.z - 2) < 1e-10);
  assert.equal(circleHits(p, 0.22, b), false);
});
test('WASD and arrows follow yaw at a bounded speed with normalized diagonals', () => {
  const w = walkDelta(new Set(['KeyW']), Math.PI / 2, 0.1);
  assert.ok(w.x < 0 && Math.abs(w.z) < 1e-10);
  const diagonal = walkDelta(new Set(['KeyW', 'KeyD']), 0, 1);
  assert.ok(Math.abs(Math.hypot(diagonal.x, diagonal.z) - 0.17) < 1e-10);
  assert.deepEqual(walkDelta(new Set(['ArrowUp']), 0, 0.1), walkDelta(new Set(['KeyW']), 0, 0.1));
  assert.equal(Math.hypot(...Object.values(walkDelta(new Set(['KeyW', 'KeyS']), 0, 0.1))), 0);
});
test('glide easing is monotonic, clamps and comes to rest at both ends', () => {
  assert.equal(glideEase(-1), 0); assert.equal(glideEase(2), 1);
  for (let i = 1; i <= 100; i++) assert.ok(glideEase(i / 100) >= glideEase((i - 1) / 100));
  assert.ok(glideEase(0.001) < 0.00001);
  assert.ok(1 - glideEase(0.999) < 0.00001);
});
test('every vantage route clears furniture and finishes at eight tenths of a second', () => {
  for (const start of Object.values(STANDING_SPOTS)) for (const end of Object.values(STANDING_SPOTS)) {
    const path = walkPath(start, end, COLLISIONS, ROOM.radius);
    assert.ok(path, `${start.name} to ${end.name}`);
    for (let i = 0; i <= 160; i++) {
      const p = glidePose(start, end, path, 0.8 * i / 160);
      assert.ok(!COLLISIONS.some(b => circleHits(p, ROOM.radius, b)), `${start.name} to ${end.name} at ${i}`);
    }
    const p = glidePose(start, end, path, 0.8);
    assert.equal(p.x, end.x); assert.equal(p.z, end.z);
    assert.ok(Math.abs(wrapYaw(p.yaw - end.yaw)) < 1e-10); assert.equal(p.pitch, end.pitch);
  }
});
test('glides rotate across the short yaw arc', () => {
  const a = { x: 0, z: 0, yaw: Math.PI - 0.1, pitch: 0 };
  const b = { ...a, yaw: -Math.PI + 0.1 };
  const p = glidePose(a, b, [a, b], 0.4);
  assert.ok(Math.abs(Math.abs(p.yaw) - Math.PI) < 1e-10);
});

test('a walk beside a rounded corner can still start a clear glide', () => {
  const boxes = [{ minX: 0, maxX: 1, minZ: 0, maxZ: 1 }];
  const start = { x: -0.17, z: -0.17, yaw: 0, pitch: 0 };
  const end = { ...start, x: -1, z: -1 };
  assert.equal(circleHits(start, 0.22, boxes[0]), false);
  assert.deepEqual(walkPath(start, end, boxes, 0.22), [start, end]);
});
