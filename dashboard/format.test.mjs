import test from 'node:test';
import assert from 'node:assert/strict';
import { plural, fmtRunMs } from './format.mjs';

test('counts agree with singular and plural nouns', () => {
  assert.equal(plural(1, 'moment'), '1 moment');
  assert.equal(plural(0, 'moment'), '0 moments');
  assert.equal(plural(2, 'moment'), '2 moments');
});

test('run times in milliseconds read as seconds', () => {
  assert.equal(fmtRunMs(0), '0.00 s');
  assert.equal(fmtRunMs(55430), '55.43 s');
  assert.equal(fmtRunMs(1234.5), '1.23 s');
});
