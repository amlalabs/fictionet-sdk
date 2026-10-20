import test from 'node:test';
import assert from 'node:assert/strict';
import { pathDiff, longestPrefix, alertText, switchState, traceLines } from './border.mjs';
import { fmtRunMs } from '../../../../dashboard/format.mjs';

test('a previous traceroute never becomes an observed new hop', () => {
  const route = { since_ms: 200, bank_hops: ['192.168.1.1', '84.21.44.1', '45.144.30.1'] };
  const trace = { started_ms: 100, complete: true, hops: ['192.168.1.1', '84.21.44.1', '84.21.44.10'].map(address => ({ address })) };
  const diff = pathDiff(route, trace, '84.21.44.10');
  assert.deepEqual(diff.observed, ['192.168.1.1', '84.21.44.1', '84.21.44.10']);
  assert.equal(diff.matches, false); assert.equal(diff.beforeChange, true);
  trace.started_ms = 300; trace.hops.splice(2, 0, { address: '45.144.30.1' });
  assert.equal(pathDiff(route, trace, '84.21.44.10').matches, true);
});
test('a closed guest link keeps its last traceroute and stops waiting', () => {
  const route = { since_ms: 200, bank_hops: ['192.168.1.1', '84.21.44.1'] };
  const trace = { started_ms: 31200, complete: true, dropped: 0, hops: ['192.168.1.1', '84.21.44.1', '84.21.44.10'].map((address, i) => ({ ttl: i + 1, address })) };
  const live = { sandbox: 'rw-desktop', ended_ms: null, trace };
  const diff = pathDiff(route, trace, '84.21.44.10');
  assert.deepEqual(traceLines(live, diff, fmtRunMs), {
    heading: 'Last observed traceroute · 31.20 s',
    hops: '1 192.168.1.1 → 2 84.21.44.1 → 3 84.21.44.10',
    note: 'The observed path matches the current route.',
  });
  const closed = { ...live, ended_ms: 57100 };
  assert.equal(traceLines(closed, diff, fmtRunMs).heading, 'Last observed traceroute · 31.20 s · guest link closed at 57.10 s');
  assert.equal(traceLines(closed, diff, fmtRunMs).hops, live.trace.hops.map(h => `${h.ttl} ${h.address}`).join(' → '));
  const partial = { ...trace, complete: false, hops: [] };
  const partialDiff = pathDiff(route, partial, '84.21.44.10');
  assert.deepEqual(traceLines({ ...live, trace: partial }, partialDiff, fmtRunMs), {
    heading: 'Last observed traceroute · 31.20 s · incomplete',
    hops: 'Waiting for replies…',
    note: 'The observed path does not yet match the complete configured path.',
  });
  assert.deepEqual(traceLines({ ...closed, trace: partial }, partialDiff, fmtRunMs), {
    heading: 'Last observed traceroute · 31.20 s · incomplete · guest link closed at 57.10 s',
    hops: 'No replies arrived.',
    note: 'The observed path does not match the complete configured path.',
  });
  assert.equal(traceLines(undefined, pathDiff(route, undefined, '84.21.44.10'), fmtRunMs).heading, 'No UDP traceroute observed on this guest link yet.');
  assert.equal(traceLines({ ...closed, trace: null }, pathDiff(route, null, '84.21.44.10'), fmtRunMs).heading, 'No UDP traceroute was observed; the guest link closed at 57.10 s.');
});
test('longest prefix is computed from the table and destination', () => {
  const routes = ['84.21.44.0/24', '84.21.44.0/25', '45.144.30.0/24'].map(prefix => ({ prefix }));
  assert.equal(longestPrefix(routes, '84.21.44.10'), '84.21.44.10 matches 84.21.44.0/24 and 84.21.44.0/25; the /25 is more specific, so it wins.');
  assert.equal(longestPrefix(routes, '84.21.44.200'), '84.21.44.200 matches 84.21.44.0/24; this route wins.');
  assert.equal(longestPrefix(routes, '10.0.0.1'), '10.0.0.1 has no matching route.');
});
test('alert text follows the classified moment', () => {
  assert.equal(alertText({ password: true }), 'The password reached the impostor');
  assert.equal(alertText({ password: false, amount_pence: 10 }), 'A payment reached the impostor');
});
test('commands settle on a reply and refusals do not retry', () => {
  assert.equal(switchState().busy, true);
  assert.deepEqual(switchState({ status: 'applied', reply: { revision: 4 } }), { busy: false, text: 'Applied at revision 4.' });
  const refused = switchState({ status: 'rejected', rejection: { reason: 'stale_revision', current: 5 } });
  assert.equal(refused.busy, false); assert.match(refused.text, /Current revision 5/);
  assert.match(switchState({ status: 'rejected', rejection: { reason: 'invalid', message: 'the route is already Normal' } }).text, /already Normal/);
  assert.match(switchState({ status: 'timeout' }).text, /may still apply/);
});

import { named, matchingSession } from './tls.mjs';
import { summarize, describe } from './results.mjs';

test('TLS identifiers keep their hex and name the offered suites', () => {
  for (const n of [0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0xff]) assert.match(named(n, 'ciphers'), /^TLS_.*\(0x[0-9a-f]{4}\)$/);
  assert.equal(named(0xff, 'ciphers'), 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)');
  assert.equal(named(0xbeef, 'ciphers'), '0xbeef');
  assert.equal(named(0x17, 'groups'), 'secp256r1 (0x0017)');
});
test('TLS matching requires both addresses and ports and refuses ambiguity', () => {
  const session = { sandbox: 'guest', client: '192.168.1.2:40123', server: '84.21.44.10:443', offered: { sni: 'bank.test' } };
  const row = { sandbox: 'guest', peer: session.client, port: 443, endpoint: {machine: '45.144.30.10', reached: '84.21.44.10'}, sni: 'bank.test' };
  assert.equal(matchingSession(session, [row]), row);
  assert.equal(matchingSession(session, [row, row]), null);
  assert.equal(matchingSession(session, [{...row, peer: '192.168.1.2:40124'}]), null);
  assert.equal(matchingSession(session, [{...row, sni: 'other.test'}]), null);
});
test('results summarize actual log classifications and explain rejections', () => {
  const lines = [{type: 'tls', identity: 'bank', outcome: 'accepted'}, {type: 'tls', identity: 'impostor', outcome: 'alert'}, {type: 'http', served_by: 'impostor', carries_password: true, page: 'login'}, {type: 'route_rejected', reason: 'already_in_mode', mode: 'hijack', revision: 1}];
  assert.deepEqual(summarize(lines), {bank: 1, impostor: 1, aborted: 1, requests: 1, passwords: 1, payments: 0, routes: [lines[3]]});
  assert.equal(describe(lines[3]), 'Route change rejected: already in that mode · Hijacked · revision 1');
});
