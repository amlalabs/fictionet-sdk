// Camera math stays independent of the renderer.
export const PITCH_LIMIT = Math.PI * 0.46;
export const wrapYaw = (angle) => Math.atan2(Math.sin(angle), Math.cos(angle));
export function look(pose, dx, dy) {
  return {
    ...pose,
    yaw: wrapYaw(pose.yaw - dx * 0.0025),
    pitch: Math.max(-PITCH_LIMIT, Math.min(PITCH_LIMIT, pose.pitch - dy * 0.0025)),
  };
}
export const glideEase = (t) => {
  const u = Math.max(0, Math.min(1, t));
  return u * u * (3 - 2 * u);
};

export function circleHits(p, radius, b) {
  const x = Math.max(b.minX, Math.min(b.maxX, p.x));
  const z = Math.max(b.minZ, Math.min(b.maxZ, p.z));
  return (p.x - x) ** 2 + (p.z - z) ** 2 < radius ** 2 - 1e-12;
}

// Small steps prevent tunneling; independent axes allow sliding along a wall.
export function walk(pose, dx, dz, boxes, radius) {
  const next = { ...pose };
  const steps = Math.max(1, Math.ceil(Math.hypot(dx, dz) / (radius * 0.45)));
  for (let i = 0; i < steps; i++) {
    const x = { ...next, x: next.x + dx / steps };
    if (!boxes.some((b) => circleHits(x, radius, b))) next.x = x.x;
    const z = { ...next, z: next.z + dz / steps };
    if (!boxes.some((b) => circleHits(z, radius, b))) next.z = z.z;
  }
  return next;
}

export function walkDelta(keys, yaw, dt) {
  const forward = Number(keys.has('KeyW') || keys.has('ArrowUp')) - Number(keys.has('KeyS') || keys.has('ArrowDown'));
  const right = Number(keys.has('KeyD') || keys.has('ArrowRight')) - Number(keys.has('KeyA') || keys.has('ArrowLeft'));
  const scale = (1.7 * Math.min(dt, 0.1)) / (Math.hypot(forward, right) || 1);
  return {
    x: (-Math.sin(yaw) * forward + Math.cos(yaw) * right) * scale,
    z: (-Math.cos(yaw) * forward - Math.sin(yaw) * right) * scale,
  };
}

function clearSegment(a, b, boxes, radius) {
  const dx = b.x - a.x,
    dz = b.z - a.z,
    lengthSquared = dx * dx + dz * dz;
  return !boxes.some((box) => {
    if (circleHits(a, radius, box) || circleHits(b, radius, box)) return true;
    let lo = 0,
      hi = 1;
    for (const [axis, min, max] of [
      ['x', box.minX, box.maxX],
      ['z', box.minZ, box.maxZ],
    ]) {
      const d = b[axis] - a[axis];
      if (Math.abs(d) < 1e-10) {
        if (a[axis] < min || a[axis] > max) {
          lo = 1;
          hi = 0;
          break;
        }
      } else {
        const t0 = (min - a[axis]) / d,
          t1 = (max - a[axis]) / d;
        lo = Math.max(lo, Math.min(t0, t1));
        hi = Math.min(hi, Math.max(t0, t1));
      }
    }
    if (lo <= hi) return true;
    // The remaining closest pairs use a box corner and the swept center line.
    return [box.minX, box.maxX].some((x) =>
      [box.minZ, box.maxZ].some((z) => {
        const t = lengthSquared ? Math.max(0, Math.min(1, ((x - a.x) * dx + (z - a.z) * dz) / lengthSquared)) : 0;
        return (x - a.x - t * dx) ** 2 + (z - a.z - t * dz) ** 2 < radius ** 2 - 1e-12;
      }),
    );
  });
}

export function walkPath(start, end, boxes, radius) {
  if (clearSegment(start, end, boxes, radius)) return [start, end];
  const gap = radius + 0.025;
  const corners = boxes
    .flatMap((b) => [b.minX - gap, b.maxX + gap].flatMap((x) => [b.minZ - gap, b.maxZ + gap].map((z) => ({ x, z }))))
    .filter((p) => !boxes.some((b) => circleHits(p, gap, b)));
  const nodes = [start, end, ...corners];
  const distance = nodes.map(() => Infinity),
    previous = [],
    visited = new Set();
  distance[0] = 0;
  for (let step = 0; step < nodes.length; step++) {
    let at = -1;
    for (let i = 0; i < nodes.length; i++) if (!visited.has(i) && (at < 0 || distance[i] < distance[at])) at = i;
    if (at < 0 || !Number.isFinite(distance[at])) return null;
    if (at === 1) {
      const path = [];
      for (let i = 1; i !== undefined; i = previous[i]) path.unshift(nodes[i]);
      return path;
    }
    visited.add(at);
    for (let i = 0; i < nodes.length; i++) {
      if (visited.has(i) || !clearSegment(nodes[at], nodes[i], boxes, radius)) continue;
      const candidate = distance[at] + Math.hypot(nodes[at].x - nodes[i].x, nodes[at].z - nodes[i].z);
      if (candidate < distance[i]) {
        distance[i] = candidate;
        previous[i] = at;
      }
    }
  }
  return null;
}

export function glidePose(start, end, path, elapsed) {
  const t = glideEase(elapsed / 0.8);
  if (t === 0) return { x: start.x, z: start.z, yaw: wrapYaw(start.yaw), pitch: start.pitch, fov: start.fov };
  if (t === 1) return { x: end.x, z: end.z, yaw: wrapYaw(end.yaw), pitch: end.pitch, fov: end.fov };
  const lengths = path.slice(1).map((p, i) => Math.hypot(p.x - path[i].x, p.z - path[i].z));
  let remaining = lengths.reduce((a, b) => a + b, 0) * t;
  let p = end;
  for (let i = 0; i < lengths.length; i++) {
    if (remaining <= lengths[i] && lengths[i] > 0) {
      const u = remaining / lengths[i];
      p = { x: path[i].x + (path[i + 1].x - path[i].x) * u, z: path[i].z + (path[i + 1].z - path[i].z) * u };
      break;
    }
    remaining -= lengths[i];
  }
  return {
    x: p.x,
    z: p.z,
    yaw: wrapYaw(start.yaw + wrapYaw(end.yaw - start.yaw) * t),
    pitch: start.pitch + (end.pitch - start.pitch) * t,
    fov: start.fov + (end.fov - start.fov) * t,
  };
}

// Only a swept crossing inside the opening changes spaces.
export function doorwayCrossing(space, previous, next, doorways, radius) {
  for (const door of doorways) {
    const forward = space === door.from && previous.z <= door.z && next.z > door.z;
    const backward = space === door.to && previous.z >= door.z && next.z < door.z;
    if (!forward && !backward) continue;
    const fraction = (door.z - previous.z) / (next.z - previous.z);
    const x = previous.x + (next.x - previous.x) * fraction;
    if (x < door.minX + radius || x > door.maxX - radius) continue;
    return forward ? door.to : door.from;
  }
  return space;
}

export function doorwayFade(elapsed, reduced) {
  if (reduced || elapsed >= 180) return 1;
  return Math.max(0, elapsed / 180);
}
