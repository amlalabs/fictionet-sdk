// Canvas coordinates and camera framing share the same physical board dimensions.
export const RADIUS = 4.6;
export const BOARD_SPAN = 40 * Math.PI / 180;
export const BOARD_BOTTOM = 0.95;
export const BOARD_TOP = 3.05;
export const BAND_BOTTOM = 3.12;
export const BAND_TOP = 4.55;
export const BOARD_PX = { width: 1600, height: Math.round(1600 * (BOARD_TOP - BOARD_BOTTOM) / (RADIUS * BOARD_SPAN)) };

export function cellLayout(width, height) {
  const font = width * 0.069;
  const line = font * 1.08;
  const pad = height * 0.006;
  const radius = Math.min(width * 0.16, (height - 5 * line - 8 * pad) / 2);
  const box = (x, y, w) => ({ x, y, w, h: line, font });
  const dialY = 2 * line + 3 * pad;
  const valueY = dialY + 2 * radius + pad;
  return {
    text: {
      label: box(width * 0.03, pad, width * 0.94),
      hmi: box(width * 0.03, line + 2 * pad, width * 0.44),
      plant: box(width * 0.53, line + 2 * pad, width * 0.44),
      reported: box(width * 0.03, valueY, width * 0.44),
      truth: box(width * 0.53, valueY, width * 0.44),
      gap: box(width * 0.14, valueY + line + pad, width * 0.83),
      held: box(width * 0.03, valueY + 2 * (line + pad), width * 0.94),
    },
    dials: [0.25, 0.75].map((x) => ({ x: width * x - radius, y: dialY, w: 2 * radius, h: 2 * radius, radius })),
    warning: { x: width * 0.03, y: valueY + line + pad, w: font, h: line },
    // The ring is inside the dial so its full stroke has reserved space.
    ringWidth: width * 0.055,
  };
}

export function boardLayout(count) {
  const { width, height } = BOARD_PX;
  const headerHeight = height * 0.1;
  const font = width / 3 * 0.069;
  const textBox = (x, y, w) => ({ x, y, w, h: headerHeight * 0.44, font });
  const cellW = width / 3;
  const cellH = (height - headerHeight) / Math.ceil(count / 3);
  return {
    header: { x: 0, y: 0, w: width, h: headerHeight },
    text: {
      title: textBox(width * 0.01, headerHeight * 0.04, width * 0.53),
      time: textBox(width * 0.56, headerHeight * 0.04, width * 0.43),
      telemetry: textBox(width * 0.01, headerHeight * 0.52, width * 0.98),
    },
    cells: Array.from({ length: count }, (_, i) => ({ x: i % 3 * cellW, y: headerHeight + Math.floor(i / 3) * cellH, w: cellW, h: cellH })),
  };
}

export function closeView(board, aspect) {
  const half = BOARD_SPAN / 2;
  const mid = (BOARD_TOP + BOARD_BOTTOM) / 2;
  const tanHalfFov = 1.05 * Math.max((BOARD_TOP - BOARD_BOTTOM) / (2 * RADIUS * Math.cos(half)), Math.tan(half) / aspect);
  return {
    eye: [0, mid, 0],
    look: [RADIUS * Math.sin(board.center), mid, RADIUS * Math.cos(board.center)],
    tanHalfFov,
    fov: 2 * Math.atan(tanHalfFov) * 180 / Math.PI,
  };
}

export function overview(aspect) {
  const half = 1.5 * BOARD_SPAN;
  const depth = 3 + RADIUS * Math.cos(half);
  const mid = (BOARD_BOTTOM + BAND_TOP) / 2;
  const tanHalfFov = Math.max(RADIUS * Math.sin(half) / (depth * aspect * 0.96), (BAND_TOP - BOARD_BOTTOM) / (2 * depth * 0.96));
  return { eye: [0, mid, 3], look: [0, mid, -RADIUS], tanHalfFov, fov: 2 * Math.atan(tanHalfFov) * 180 / Math.PI };
}

// Vertical texel scale is smallest at the center of the arc for the close view.
export function closePixelScale(width, height) {
  const view = closeView({ center: Math.PI }, width / height);
  return height / (2 * view.tanHalfFov * RADIUS) * (BOARD_TOP - BOARD_BOTTOM) / BOARD_PX.height;
}

// Bound the stroke scale in both directions, including shear at the arc edges.
export function overviewPixelScale(width, height) {
  const view = overview(width / height);
  const angle = 1.5 * BOARD_SPAN;
  const depth = 3 + RADIUS * Math.cos(angle);
  const horizontal = (RADIUS + 3 * Math.cos(angle)) / (depth * depth);
  const vertical = 1 / (RADIUS + 3);
  const shearBound = (BAND_TOP - BOARD_BOTTOM) / 2 * Math.sin(angle) / (RADIUS + 3 * Math.cos(angle));
  return height / (2 * view.tanHalfFov) * Math.min(horizontal, vertical) / (1 + shearBound) * (BOARD_TOP - BOARD_BOTTOM) / BOARD_PX.height;
}
