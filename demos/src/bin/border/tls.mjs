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
  const el = (tag, text, parent = root, cls = '') => { const n = root.ownerDocument.createElement(tag); n.textContent = text; n.className = cls; parent.append(n); return n; };
  const css = el('link', ''); css.rel = 'stylesheet'; css.href = '/assets/border.css';
  el('h2', 'TLS on the guest link');
  el('p', 'ClientHello and ServerHello fields from captured TCP bytes. The world offers no post-quantum key exchange. Missing fields stay unknown.');
  const status = el('p', 'Waiting for captured TLS hellos…'); const rows = el('div', '');
  let capture, facts = [];
  function render() {
    if (!capture) return;
    const {value, status: state} = capture;
    status.textContent = `${value.sessions.length} retained session${value.sessions.length === 1 ? '' : 's'} · older sessions dropped: ${value.dropped} · packets lost: ${value.lost}${state?.too_large ? ' · publication exceeded its limit' : ''}`;
    rows.replaceChildren();
    for (const s of value.sessions.toReversed()) {
      const item = el('details', '', rows, 'border-inspector-session'); item.open = true;
      el('summary', `${(s.at_ms / 1000).toFixed(2)} s · ${s.client} → ${s.server}`, item);
      el('p', `Captured on ${s.sandbox}’s link · capture or decoding gaps: ${s.gaps}`, item);
      const fact = matchingSession(s, facts);
      el('p', `SNI: ${s.offered?.sni || fact?.sni || 'not captured'}`, item);
      el('p', fact ? `Answered by ${fact.identity === 'bank' ? 'the bank' : fact.identity === 'impostor' ? 'the impostor’s machine' : 'machine'} ${fact.endpoint.machine}, at ${fact.endpoint.reached} · ${fact.outcome} · approximate match by addresses and ports to connection ${fact.connection ?? 'unknown'}.` : 'Answering machine not matched to an observed TLS session.', item);
      el('p', `Legacy version fields: client ${s.offered ? named(s.offered.legacy_version, 'versions') : 'not captured'} · server ${s.chosen ? named(s.chosen.legacy_version, 'versions') : 'not captured'}`, item);
      const table = el('table', '', item, 'border-tls-table');
      const head = el('tr', '', el('thead', '', table));
      for (const text of ['Identifier', 'Offered', 'Chosen']) el('th', text, head);
      const body = el('tbody', '', table);
      for (const [label, key] of [['Versions', 'versions'], ['Cipher suites', 'ciphers'], ['Groups', 'groups'], ['Key shares', 'key_shares']]) {
        const group = el('tr', '', body, 'border-tls-group'); el('th', label, group).colSpan = 3;
        const offered = s.offered?.[key] || [], chosen = s.chosen?.[key] || [];
        const union = [...new Set([...offered, ...chosen])];
        if (!union.length) el('td', 'Not present in captured hellos', el('tr', '', body)).colSpan = 3;
        for (const n of union) {
          const row = el('tr', '', body); el('td', named(n, key), row);
          el('td', offered.includes(n) ? 'yes' : '—', row);
          el('td', chosen.includes(n) ? 'yes' : '—', row);
        }
      }
      if (!s.offered || !s.chosen) el('p', 'A complete hello was not captured for both directions.', item);

    }
  }
  const failed = error => { status.textContent = `Could not read TLS captures: ${error.message}`; };
  const stops = [services.state(options.state, snapshot => { if (snapshot.value) { capture = snapshot; render(); } }, failed), services.state('/api/state/border', ({value}) => { facts = value?.tls?.rows || []; render(); }, failed)];
  return () => { stops.forEach(stop => stop()); root.replaceChildren(); };
}
