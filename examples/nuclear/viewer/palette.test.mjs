import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PALETTE_TOKENS, paletteReady } from './control-room.mjs';
const css = readFileSync(new URL('./viewer.css', import.meta.url), 'utf8');
const palettes = [...css.matchAll(/--surface:\s*#[\da-f]+;[\s\S]*?--coolant-hot:\s*#[\da-f]+;/g)];

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

