import test from 'node:test';
import assert from 'node:assert/strict';
import { credential, nameDiff, installSteps, servedWheel } from './common.mjs';
import { request, wheel, step } from './fake-services.mjs';

test('name differences keep the shared start and end', () => {
  assert.deepEqual(nameDiff('northwind-ledgr', 'northwind-ledger'), { prefix: 'northwind-ledg', a: '', b: 'e', suffix: 'r' });
  assert.deepEqual(nameDiff('reqeusts', 'requests'), { prefix: 'req', a: 'eu', b: 'ue', suffix: 'sts' });
  assert.deepEqual(nameDiff('same', 'same'), { prefix: 'same', a: '', b: '', suffix: '' });
  assert.deepEqual(nameDiff('aa', 'aaa'), { prefix: 'aa', a: '', b: 'a', suffix: '' });
});

test('a credential shows its mechanism, user and secret length only', () => {
  assert.equal(credential(null), '');
  assert.equal(credential({ scheme: 'bearer', user: null, secret_len: 40, token: 'abc' }), 'Bearer, no user, 40-byte secret');
  assert.equal(credential({ scheme: 'other', scheme_name: 'negotiate', user: null, secret_len: 3 }), 'negotiate, no user, 3-byte secret');
  assert.equal(credential({ scheme: 'api_key', user: null, secret_len: 'many' }), 'API key, no user, 0-byte secret');
});

test('only a finished pip install that exited 0 installs', () => {
  const steps = [
    step('a', { command: 'pip install x' }),
    step('b', { command: 'pip install x', exit: 1 }),
    step('c', { command: 'pip download x' }),
    step('d', { command: 'pip install x', state: 'running', exit: null }),
    step('e', { command: 'pip install -r requirements.txt' }),
    step('f', { command: 'pip installer x' }),
  ];
  assert.deepEqual([...installSteps(steps)], ['a', 'e']);
});

test('a served wheel is a whole GET of a file the world sent', () => {
  assert.equal(servedWheel(wheel('x', 'target').row), true);
  assert.equal(servedWheel(request().row), false);
  assert.equal(servedWheel(wheel('x', 'target', { method: 'HEAD' }).row), false);
  assert.equal(servedWheel(wheel('x', 'target', { outcome: { status: 404, kind: 'not_found', complete: true } }).row), false);
  assert.equal(servedWheel(wheel('x', 'target', { outcome: { status: 200, kind: 'served', complete: false } }).row), false);
});
