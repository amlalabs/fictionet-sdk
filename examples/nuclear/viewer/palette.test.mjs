import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

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
      ['text', 'surface-raised'],
      ['text', 'surface'],
      ['warning', 'surface-raised'],
      ['surface', 'warning'],
    ]) {
      const light = Math.max(colors[foreground], colors[background]);
      const dark = Math.min(colors[foreground], colors[background]);
      const contrast = (light + 0.05) / (dark + 0.05);
      assert.ok(contrast >= 4.5, `Palette ${index}: ${foreground} on ${background} is ${contrast}`);
    }
  }
});
