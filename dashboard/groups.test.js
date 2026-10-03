// Tests for groups.js: `node --test dashboard/groups.test.js`. The Rust
// test `dashboard_js` runs them when node is installed.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const G = require('./groups.js');

// A small world: a router, and a group "office" with a nested group
// "printer". The sandbox is read by a delay in the group "uplink".
//
//   agent ── delay ── router ── split ── tcp
//            uplink           office › printer
//
// plus a second link from the router into "office", to its DNS.
function world() {
  const groups = new Map(
    [
      { id: 'g1', name: 'office', parent: null },
      { id: 'g2', name: 'printer', parent: 'g1' },
      { id: 'g3', name: 'uplink', parent: null },
    ].map((g) => [g.id, g]),
  );
  const node = (id, kind, name, group) => ({ id, kind, name, group, edges: new Set() });
  const nodes = [
    node('s9', 'sandbox', 'agent', 'g3'),
    node('t2', 'task', 'delay', 'g3'),
    node('t3', 'task', 'router', null),
    node('t4', 'task', 'split_protocols', 'g2'),
    node('t5', 'task', 'tcp::endpoint', 'g2'),
    node('t6', 'task', 'dns', 'g1'),
    // A task with no links, such as one per connection: never drawn.
    node('t7', 'task', 'serve', 'g2'),
  ];
  const link = (id, a, b, c, label = null) => ({ id, a, b, c, label });
  const links = [
    link('e1', 't2', 's9', [10, 1000, 20, 2000]),
    link('e2', 't3', 't2', [1, 100, 2, 200]),
    link('e3', 't3', 't4', [5, 500, 6, 600], '10.0.0.5/32'),
    link('e4', 't4', 't5', [7, 700, 8, 800]),
    link('e5', 't6', 't3', [3, 300, 4, 400]),
  ];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  for (const e of links) {
    byId.get(e.a).edges.add(e.id);
    byId.get(e.b).edges.add(e.id);
  }
  return { groups, nodes, links };
}

test('groups know their path, depth and what they hold', () => {
  const { groups, nodes } = world();
  const info = G.info(groups, nodes);
  assert.deepEqual(info.get('g2'), { key: 'office › printer', depth: 1, leaves: 2, sandboxes: 0, tasks: 3 });
  assert.deepEqual(info.get('g1'), { key: 'office', depth: 0, leaves: 3, sandboxes: 0, tasks: 4 });
  assert.deepEqual(info.get('g3'), { key: 'uplink', depth: 0, leaves: 2, sandboxes: 1, tasks: 1 });
  assert.deepEqual(G.chain(groups, 'g2').map((g) => g.name), ['office', 'printer']);
  // Outermost groups start open, nested ones closed.
  assert.equal(G.openByDefault(info.get('g1')), true);
  assert.equal(G.openByDefault(info.get('g2')), false);
});

test('two groups with one path get different keys', () => {
  const groups = new Map([
    ['g1', { id: 'g1', name: 'host', parent: null }],
    ['g2', { id: 'g2', name: 'host', parent: null }],
  ]);
  const info = G.info(groups, []);
  assert.equal(info.get('g1').key, 'host');
  assert.equal(info.get('g2').key, 'host #2');
});

test('with every group open, each link is its own edge', () => {
  const { groups, nodes, links } = world();
  const agg = G.aggregate(groups, nodes, links, () => true);
  assert.equal(agg.owner.get('t5'), 't5');
  assert.equal(agg.owner.has('t7'), false, 'a task with no links is not drawn');
  assert.deepEqual([...agg.closed], []);
  assert.deepEqual([...agg.frames].sort(), ['g1', 'g2', 'g3']);
  assert.equal(agg.contOf.get('t5'), 'g2');
  assert.equal(agg.contOf.get('f:g2'), 'g1');
  assert.equal(agg.contOf.get('t3'), null);
  assert.deepEqual(agg.edges.map((d) => d.id).sort(), ['e1', 'e2', 'e3', 'e4', 'e5']);
  const e3 = agg.edges.find((d) => d.id === 'e3');
  assert.equal(e3.label, '10.0.0.5/32');
  assert.deepEqual([e3.a, e3.b], ['t3', 't4']);
});

test('a closed group stands for everything inside it, nested groups too', () => {
  const { groups, nodes, links } = world();
  const agg = G.aggregate(groups, nodes, links, (gid) => gid !== 'g1');
  for (const id of ['t4', 't5', 't6']) assert.equal(agg.owner.get(id), 'g1');
  assert.deepEqual([...agg.closed], ['g1']);
  assert.deepEqual([...agg.frames], ['g3'], 'a group inside a closed one has no frame');
  // The link inside the group is not drawn. The two links that cross its
  // edge, from the router, are drawn as one, with their counts added the
  // same way round.
  assert.equal(agg.edges.find((d) => d.members.some((m) => m.e.id === 'e4')), undefined);
  const crossing = agg.edges.find((d) => d.members.length === 2);
  assert.deepEqual([crossing.a, crossing.b], ['g1', 't3']);
  assert.deepEqual(crossing.members.map((m) => [m.e.id, m.flip]), [
    ['e3', true],
    ['e5', false],
  ]);
  // e3 goes router → split (flipped: 5 packets from b), e5 dns → router.
  assert.deepEqual(G.counts(crossing), [6 + 3, 600 + 300, 5 + 4, 500 + 400]);
  assert.equal(crossing.label, '10.0.0.5/32', 'the one route label is kept');
  const rate = (e) => (e.id === 'e3' ? [1, 2] : [10, 20]);
  assert.deepEqual(G.rates(crossing, rate), [2 + 10, 1 + 20]);
});

test('a closed group with a sandbox inside draws the sandbox as the group', () => {
  const { groups, nodes, links } = world();
  const agg = G.aggregate(groups, nodes, links, (gid) => gid !== 'g3');
  assert.equal(agg.owner.get('s9'), 'g3');
  assert.equal(agg.owner.get('t2'), 'g3');
  const up = agg.edges.find((d) => d.a === 'g3' || d.b === 'g3');
  assert.equal(up.id, 'e2', 'one crossing link keeps its own id');
  assert.deepEqual([up.a, up.b], ['t3', 'g3']);
});

test('a link between two closed groups is drawn between the groups', () => {
  const { groups, nodes, links } = world();
  links.push({ id: 'e6', a: 't2', b: 't6', c: [1, 1, 1, 1], label: null });
  nodes.find((n) => n.id === 't2').edges.add('e6');
  nodes.find((n) => n.id === 't6').edges.add('e6');
  const agg = G.aggregate(groups, nodes, links, () => false);
  const between = agg.edges.find((d) => d.members.some((m) => m.e.id === 'e6'));
  assert.deepEqual([between.a, between.b], ['g3', 'g1']);
});
