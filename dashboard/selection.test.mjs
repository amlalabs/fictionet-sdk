import test from 'node:test';
import assert from 'node:assert/strict';
import { createSelection } from './selection.mjs';

test('selection shares explicit identities and subscriptions release their listeners', () => {
  const selection = createSelection(), seen = [];
  const off = selection.subscribe((value) => seen.push(value));
  const links = ['e1', 'e2'];
  selection.set({ host: 'alpha', node: 'n1', links });
  links.push('e3');
  assert.deepEqual(selection.get().links, ['e1', 'e2']);
  assert.throws(() => selection.get().links.push('e4'), TypeError);
  assert.throws(() => { selection.get().host = 'beta'; }, TypeError);
  selection.set({ event: { at: 4 } });
  assert.equal(selection.get().connection, null);
  assert.equal(selection.get().request, null);
  assert.equal(selection.get().host, 'alpha');
  off();
  selection.set({ host: null });
  assert.equal(seen.length, 3);
  assert.throws(() => selection.set({ time: 1 }), /Unknown selection field/);
});
