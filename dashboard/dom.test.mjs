import test from 'node:test';
import assert from 'node:assert/strict';
import { reconcile } from './dom.mjs';
import { createDocument } from './test-dom.mjs';

test('reconcile creates, updates, removes and moves keyed rows without rebuilding them', () => {
  const document = createDocument();
  const parent = document.createElement('ul');
  const retained = new Map(), created = [], updates = [];
  const key = (item) => item.id;
  const create = (item) => { created.push(item.id); return { node: document.createElement('li') }; };
  const update = (entry, item, fresh) => { entry.node.textContent = item.text; updates.push([item.id, fresh]); };
  let moves = 0;
  const insert = parent.insertBefore.bind(parent);
  parent.insertBefore = (...args) => { moves++; return insert(...args); };

  reconcile(parent, [{ id: 'a', text: 'A' }, { id: 'b', text: 'B' }, { id: 'c', text: 'C' }], key, create, update, retained);
  assert.equal(parent.textContent, 'ABC');
  assert.deepEqual(updates, [['a', true], ['b', true], ['c', true]]);
  const [a, b, c] = parent.children;

  // A new row at the top, one row gone and one changed: the others keep their
  // nodes, and only the new row is inserted.
  moves = 0;
  reconcile(parent, [{ id: 'd', text: 'D' }, { id: 'a', text: 'A2' }, { id: 'c', text: 'C' }], key, create, update, retained);
  assert.equal(parent.textContent, 'DA2C');
  assert.equal(parent.children[1], a);
  assert.equal(parent.children[2], c);
  assert.equal(b.parent, null);
  assert.equal(moves, 1);
  assert.deepEqual(updates.slice(3), [['d', true], ['a', false], ['c', false]]);
  const d = parent.children[0];

  // A new order moves nodes and creates none.
  moves = 0;
  reconcile(parent, [{ id: 'c', text: 'C' }, { id: 'd', text: 'D' }, { id: 'a', text: 'A2' }], key, create, update, retained);
  assert.deepEqual(parent.children, [c, d, a]);
  assert.equal(moves, 1);
  assert.deepEqual(created, ['a', 'b', 'c', 'd']);

  reconcile(parent, [], key, create, update, retained);
  assert.equal(parent.children.length, 0);
  assert.equal(retained.size, 0);
});
