const hex = n => `0x${n.toString(16).padStart(4, '0')}`;
const versions = { 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
const ciphers = { 0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256', 0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV' };
const groups = { 0x001d: 'X25519', 0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1', 0x001e: 'X448', 0x0100: 'ffdhe2048', 0x0101: 'ffdhe3072' };
export const named = (n, kind) => { const name = ({ versions, ciphers, groups, key_shares: groups }[kind] || {})[n]; return name ? `${name} (${hex(n)})` : hex(n); };
export function matchingSession(session, rows) {
  const matches = rows.filter(row => row.sandbox === session.sandbox && row.peer === session.client && `${row.endpoint.reached}:${row.port}` === session.server && (!session.offered?.sni || row.sni === session.offered.sni));
  return matches.length === 1 ? matches[0] : null;
}
export function mount(root, services, options) {
  const { reconcile } = services.dom, { plural, fmtRunMs } = services.format;
  const { el } = services.dom.scoped(root);
  el('link', { rel: 'stylesheet', href: '/assets/border.css' }, root);
  el('h2', { text: 'TLS on the guest link' }, root);
  el('p', { text: 'ClientHello and ServerHello fields from captured TCP bytes. The world offers no post-quantum key exchange. Missing fields stay unknown.' }, root);
  const status = el('p', { text: 'Waiting for captured TLS hellos…' }, root); const rows = el('div', {}, root);
  let capture, facts = [];
  const sessions = new Map();
  function render() {
    if (!capture) return;
    const {value, status: state} = capture;
    status.textContent = `${plural(value.sessions.rows.length, 'retained session')} · older sessions dropped: ${value.sessions.dropped} · packets lost: ${value.lost}${state?.too_large ? ' · publication exceeded its limit' : ''}`;
    // A session keeps its element, so one the viewer closed stays closed.
    reconcile(rows, value.sessions.rows.toReversed(), (s) => JSON.stringify([s.at_ms, s.sandbox, s.client, s.server]), () => {
      const node = el('details', { class: 'border-inspector-session' }, null);
      node.open = true;
      return { node, shown: '' };
    }, (entry, s) => {
      const shown = JSON.stringify([s, matchingSession(s, facts)]);
      if (shown !== entry.shown) { entry.shown = shown; session(entry.node, s); }
    }, sessions);
  }
  function session(item, s) {
    item.replaceChildren();
    el('summary', { text: `${fmtRunMs(s.at_ms)} · ${s.client} → ${s.server}` }, item);
    el('p', { text: `Captured on ${s.sandbox}’s link · capture or decoding gaps: ${s.gaps}` }, item);
    const fact = matchingSession(s, facts);
    el('p', { text: `SNI: ${s.offered?.sni || fact?.sni || 'not captured'}` }, item);
    el('p', { text: fact ? `Answered by ${fact.identity === 'bank' ? 'the bank' : fact.identity === 'impostor' ? 'the impostor’s machine' : 'machine'} ${fact.endpoint.machine}, at ${fact.endpoint.reached} · ${fact.outcome} · approximate match by addresses and ports to connection ${fact.connection ?? 'unknown'}.` : 'Answering machine not matched to an observed TLS session.' }, item);
    el('p', { text: `Legacy version fields: client ${s.offered ? named(s.offered.legacy_version, 'versions') : 'not captured'} · server ${s.chosen ? named(s.chosen.legacy_version, 'versions') : 'not captured'}` }, item);
    const table = el('table', { class: 'border-tls-table' }, item);
    const head = el('tr', {}, el('thead', {}, table));
    for (const text of ['Identifier', 'Offered', 'Chosen']) el('th', { text }, head);
    const body = el('tbody', {}, table);
    for (const [label, key] of [['Versions', 'versions'], ['Cipher suites', 'ciphers'], ['Groups', 'groups'], ['Key shares', 'key_shares']]) {
      const group = el('tr', { class: 'border-tls-group' }, body); el('th', { text: label }, group).colSpan = 3;
      const offered = s.offered?.[key] || [], chosen = s.chosen?.[key] || [];
      const union = [...new Set([...offered, ...chosen])];
      if (!union.length) el('td', { text: 'Not present in captured hellos' }, el('tr', {}, body)).colSpan = 3;
      for (const n of union) {
        const row = el('tr', {}, body); el('td', { text: named(n, key) }, row);
        el('td', { text: offered.includes(n) ? 'yes' : '—' }, row);
        el('td', { text: chosen.includes(n) ? 'yes' : '—' }, row);
      }
    }
    if (!s.offered || !s.chosen) el('p', { text: 'A complete hello was not captured for both directions.' }, item);
  }
  const failed = error => { status.textContent = `Could not read TLS captures: ${error.message}`; };
  const stops = [services.state(options.state, snapshot => { if (snapshot.value) { capture = snapshot; render(); } }, failed), services.state('/api/state/border', ({value}) => { facts = value?.tls?.rows || []; render(); }, failed)];
  return () => { stops.forEach(stop => stop()); root.replaceChildren(); };
}
