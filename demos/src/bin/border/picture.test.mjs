import test from 'node:test';
import assert from 'node:assert/strict';
import { route, stolen, rows, clock } from './picture.mjs';

test('the route follows the world state, with the impostor on unless it says off', () => {
  assert.deepEqual(route(null), { hijacked: false, impostor: true, revision: null });
  assert.deepEqual(route({ mode: 'hijack', impostor: false, revision: 4 }), { hijacked: true, impostor: false, revision: 4 });
  assert.deepEqual(route({ mode: 'legitimate', impostor: true, revision: 0 }), { hijacked: false, impostor: true, revision: 0 });
});

test('the newest password at the impostor is the theft; a payment alone is not', () => {
  assert.equal(stolen(null), null);
  assert.equal(stolen({ moments: { rows: [{ event: 3, at_ms: 10, password: false }] } }), null);
  const view = { moments: { rows: [{ event: 3, at_ms: 10, password: true }, { event: 9, at_ms: 20, password: true }, { event: 11, at_ms: 30, password: false }] } };
  assert.deepEqual(stolen(view), { event: 9, at: 20 });
});

test('rows come newest first, at most six, named as the picture names them', () => {
  const view = { rows: { rows: Array.from({ length: 8 }, (_, i) => ({ at_ms: i * 1000, event: i, from: 'workstation', to: i === 7 ? 'impostor' : null, what: `step ${i}`, tone: i === 7 ? 'hot' : '' })) } };
  const shown = rows(view);
  assert.equal(shown.length, 6);
  assert.deepEqual(shown[0], { id: 7, at: 7000, who: 'workstation → impostor', what: 'step 7', tone: 'hot' });
  assert.equal(shown[1].who, 'workstation');
  assert.deepEqual(shown.map((r) => r.id), [7, 6, 5, 4, 3, 2]);
  assert.deepEqual(rows(null), []);
});

test('run time reads as minutes and seconds', () => {
  assert.equal(clock(0), '0:00');
  assert.equal(clock(65_400), '1:05');
});
