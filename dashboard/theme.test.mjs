import test from 'node:test';
import assert from 'node:assert/strict';
import { createTheme } from './theme.mjs';
import { createDocument, Element } from './test-dom.mjs';

test('theme follows the system until chosen and releases button and media listeners', () => {
  const document = createDocument(), button = document.createElement('button');
  const media = new Element('media'), stored = new Map();
  media.matches = false;
  const theme = createTheme(button, {
    document, location: { search: '' }, matchMedia: () => media,
    storage: { getItem: (k) => stored.get(k), setItem: (k, v) => stored.set(k, v) },
  });
  const seen = [];
  const off = theme.subscribe((scheme) => seen.push(scheme));
  assert.equal(theme.current(), 'light');
  assert.equal(document.documentElement.dataset.theme, undefined);
  media.matches = true;
  media.dispatchEvent(new Event('change'));
  assert.equal(theme.current(), 'dark');
  button.click();
  assert.equal(stored.get('fictionet-theme'), 'light');
  assert.equal(document.documentElement.dataset.theme, 'light');
  assert.equal(button.getAttribute('aria-label'), 'Switch to dark theme');
  assert.deepEqual(seen, ['light', 'dark', 'light']);
  off();
  theme.dispose();
  assert.equal(button.listenerCount + media.listenerCount, 0);
  button.click();
  assert.equal(theme.current(), 'light');
});

test('theme works when storage refuses access and URL choice wins over storage', () => {
  for (const search of ['', '?theme=dark']) {
    const document = createDocument(), button = document.createElement('button');
    const media = new Element('media');
    media.matches = false;
    const theme = createTheme(button, {
      document, location: { search }, matchMedia: () => media,
      storage: { getItem() { throw new Error('disabled'); }, setItem() { throw new Error('disabled'); } },
    });
    assert.equal(theme.current(), search ? 'dark' : 'light');
    button.click();
    assert.equal(theme.current(), search ? 'light' : 'dark');
    theme.dispose();
  }
});
