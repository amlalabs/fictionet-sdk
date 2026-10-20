import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PALETTE_TOKENS, paletteReady } from './control-room.mjs';

const css = readFileSync(new URL('./viewer.css', import.meta.url), 'utf8');
const palettes = [...css.matchAll(/--surface:\s*#[\da-f]+;[\s\S]*?--coolant-hot:\s*#[\da-f]+;/g)];

function luminance(hex) {
  const channels = hex.match(/[\da-f]{2}/g).map((channel) => {
    const value = parseInt(channel, 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

test('the light, automatic dark and explicit dark board palettes have readable text', () => {
  assert.equal(palettes.length, 3);
  for (const [index, [block]] of palettes.entries()) {
    const colors = Object.fromEntries(
      [...block.matchAll(/--([\w-]+):\s*#([\da-f]+);/g)].map(([, name, hex]) => [name, luminance(hex)]),
    );
    for (const [foreground, background] of [
      ['ink', 'surface-raised'],
      ['ink', 'surface'],
      ['ink', 'surface-sunken'],
      ['surface', 'ink'],
      ['text', 'surface-raised'],
      ['text', 'surface'],
      ['warning', 'surface-raised'],
      ['surface', 'warning'],
      ['lamp-ink', 'lamp-glow'],
      ['lamp-legend', 'lamp-off'],
    ]) {
      const light = Math.max(colors[foreground], colors[background]);
      const dark = Math.min(colors[foreground], colors[background]);
      const contrast = (light + 0.05) / (dark + 0.05);
      assert.ok(contrast >= 4.5, `Palette ${index}: ${foreground} on ${background} is ${contrast}`);
    }
  }
});

test('lamp states and window borders have graphic contrast in every theme', () => {
  for (const [block] of palettes) {
    const colors = Object.fromEntries(
      [...block.matchAll(/--([\w-]+):\s*#([\da-f]+);/g)].map(([, name, hex]) => [name, luminance(hex)]),
    );
    for (const [a, b] of [
      ['lamp-glow', 'lamp-off'],
      ['ink', 'steel'],
      ['warning', 'steel'],
    ]) {
      const contrast = (Math.max(colors[a], colors[b]) + 0.05) / (Math.min(colors[a], colors[b]) + 0.05);
      assert.ok(contrast >= 3, `${a} against ${b}: ${contrast}`);
    }
    for (const name of ['plant-key', 'rubber', 'lamp-glow', 'lamp-off', 'lamp-ink', 'lamp-legend']) {
      assert.ok(Number.isFinite(colors[name]), `${name} is defined in each theme`);
    }
  }
});

test('view colors are ready only when every required token has a value', () => {
  assert.equal(paletteReady({}), false);
  const base = css.match(/:root\s*\{([^}]+)\}/)[1];
  for (const [block] of palettes) {
    const tokens = Object.fromEntries(
      [...(base + block).matchAll(/(--[\w-]+):\s*(#[\da-f]+);/g)].map(([, name, color]) => [name, color]),
    );
    const values = Object.fromEntries(Object.entries(PALETTE_TOKENS).map(([name, token]) => [name, tokens[token]]));
    assert.equal(paletteReady(values), true);
    for (const name of Object.keys(PALETTE_TOKENS)) {
      for (const missing of [undefined, null, '', '  \n ']) {
        assert.equal(paletteReady({ ...values, [name]: missing }), false, name);
      }
      const partial = { ...values };
      delete partial[name];
      assert.equal(paletteReady(partial), false, name);
    }
  }
});

test('forced colors preserve meter text and warning contrast with system colors', () => {
  const block = css.match(/@media \(forced-colors: active\)\s*\{\s*:root, :root\[data-theme\]\s*\{([^}]+)\}/)[1];
  const colors = Object.fromEntries(
    [...block.matchAll(/--([\w-]+):\s*(\w+);/g)].map(([, name, color]) => [name, color]),
  );
  for (const name of ['surface', 'surface-raised', 'surface-sunken', 'steel']) assert.equal(colors[name], 'Canvas');
  for (const name of ['ink', 'text', 'warning', 'line', 'line-strong']) assert.equal(colors[name], 'CanvasText');
  assert.notEqual(colors.rubber, colors['lamp-legend']);
});

test('vantage buttons stay below a wide canvas in one fitted row with visible focus', () => {
  const styles = readFileSync(new URL('./control-room.css', import.meta.url), 'utf8');
  const stage = styles.match(/\.cr-stage\s*\{([^}]+)\}/)[1];
  const row = styles.match(/\.cr-vantages\s*\{([^}]+)\}/)[1];
  const button = styles.match(/\.cr-vantage\s*\{([^}]+)\}/)[1];
  assert.match(stage, /aspect-ratio:\s*16\s*\/\s*10/);
  assert.doesNotMatch(stage, /height:\s*100%/);
  assert.match(row, /flex-wrap:\s*nowrap/);
  assert.doesNotMatch(row, /overflow[^:]*:\s*(auto|scroll|hidden)/);
  assert.doesNotMatch(row, /position:\s*absolute/);
  assert.ok(Number(button.match(/min-height:\s*(\d+)px/)[1]) >= 24);
  assert.match(styles, /:focus-visible\s*\{[^}]*outline:/);
  assert.match(styles, /@media\s*\(prefers-reduced-motion:\s*reduce\)/);
  assert.match(styles, /@media\s*\(forced-colors:\s*active\)/);
});

test('all ten vantage labels fit the smaller measured canvas with full accessible names', (t) => {
  const source = readFileSync(new URL('./control-room.mjs', import.meta.url), 'utf8');
  const styles = readFileSync(new URL('./control-room.css', import.meta.url), 'utf8');
  const sourceRow = source.slice(source.indexOf('  const vantageButtons = ['), source.indexOf('  const controlStage'));
  const labels = [...sourceRow.matchAll(/\['([^']+)', '([^']+)', ([^\n]+)\],/g)];
  assert.deepEqual(
    labels.map((match) => match[2]),
    ['Room', 'RPS', 'RCS', 'Loops', 'SG / feed', 'Turbine', 'CCTV', 'Door', 'Containment', 'Turbine hall'],
  );
  assert.deepEqual(
    labels.map((match) => match[1]),
    [
      'control-room',
      'rps-board',
      'rcs-board',
      'loops-board',
      'feed-board',
      'turbine-board',
      'cctv',
      'door',
      'reactor',
      'turbine',
    ],
  );
  assert.match(sourceRow, /'aria-label': accessible/);
  for (const match of labels.slice(0, 8)) assert.match(match[3], /STANDING_SPOTS/);
  const row = styles.match(/\.cr-vantages\s*\{([^}]+)\}/)[1];
  const button = styles.match(/\.cr-vantage\s*\{([^}]+)\}/)[1];
  const font = Number(button.match(/font-size:\s*([\d.]+)rem/)[1]) * 16;
  const padding = Number(button.match(/padding:\s*\d+px\s+(\d+)px/)[1]);
  const border = Number(button.match(/border:\s*(\d+)px/)[1]);
  const gap = Number(row.match(/gap:\s*(\d+)px/)[1]);
  const outer = Number(row.match(/padding:\s*(\d+)px/)[1]);
  const width =
    labels.reduce((sum, match) => sum + match[2].length * font * 0.65 + 2 * (padding + border), 0) +
    (labels.length - 1) * gap +
    2 * outer;
  assert.ok(width <= 692, `${width} px`);
  t.diagnostic(`Estimated chip row ${width.toFixed(1)} px of 692 px.`);
});
