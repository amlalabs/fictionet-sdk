const words = value => String(value).replaceAll('_', ' ');
const mode = value => value === 'hijack' ? 'Hijacked' : value === 'legitimate' ? 'Normal' : words(value);
export function summarize(lines) {
  const tls = lines.filter(l => l.type === 'tls');
  const requests = lines.filter(l => l.type === 'http' && l.served_by === 'impostor');
  return {
    bank: tls.filter(l => l.identity === 'bank').length,
    impostor: tls.filter(l => l.identity === 'impostor').length,
    aborted: tls.filter(l => l.outcome === 'alert').length,
    requests: requests.length,
    passwords: requests.filter(l => l.carries_password === true).length,
    payments: requests.filter(l => l.page === 'payment').length,
    routes: lines.filter(l => l.type === 'route' || l.type === 'route_rejected'),
  };
}
export function describe(line) {
  if (line.type === 'route') return `Route changed to ${mode(line.mode)} · revision ${line.revision}`;
  if (line.type === 'route_rejected') return `Route change rejected: ${line.reason === 'already_in_mode' ? 'already in that mode' : words(line.reason)} · ${mode(line.mode)} · revision ${line.revision}`;
  if (line.type === 'tls') return `TLS · ${line.identity || 'unknown identity'} · ${line.outcome === 'alert' ? `client aborted (${words(line.alert || 'alert')})` : words(line.outcome)}`;
  if (line.type === 'http') return `Impostor answered ${line.method} ${line.path}${line.carries_password ? ' · password received' : ''}${line.page === 'payment' ? ' · payment received' : ''}`;
  return words(line.type);
}
export function mount(root, services, options) {
  const { reconcile } = services.dom, { plural, fmtRunMs } = services.format;
  const el = (tag, text, parent = root) => { const n = root.ownerDocument.createElement(tag); n.textContent = text; parent?.append(n); return n; };
  const css = el('link', ''); css.rel = 'stylesheet'; css.href = '/assets/border.css';
  el('h2', 'From the world’s log');
  el('p', 'The log for this run, which the eval’s scorer reads. Counts cover the retained lines below.');
  const status = el('p', 'Waiting for log lines…');
  const summary = el('div', ''); summary.className = 'border-inspector-summary';
  const changes = el('div', ''); const rows = el('div', '');
  el('h3', 'In time order', rows);
  const list = el('div', '', rows);
  const aligned = el('p', 'Approximate run times align log timestamps to the route change’s recorded run time.', rows);
  aligned.hidden = true;
  const lines = new Map();
  const stop = services.state(options.state, ({ value, status: state }) => {
    if (!value) return;
    status.textContent = `${plural(value.lines.length, 'retained line')} · dropped: ${value.dropped} · unreadable: ${value.invalid}${state?.too_large ? ' · publication exceeded its limit' : ''}`;
    const result = summarize(value.lines); summary.replaceChildren(); changes.replaceChildren();
    for (const text of [`Bank: ${plural(result.bank, 'TLS session')}`, `Impostor: ${plural(result.impostor, 'TLS session')}`, `Client aborted: ${plural(result.aborted, 'TLS session')}`, `Impostor answered: ${plural(result.requests, 'request')}`, `Password reached impostor: ${result.passwords ? 'yes' : 'no'} (${result.passwords})`, `Payment reached impostor: ${result.payments ? 'yes' : 'no'} (${result.payments})`]) el('p', text, summary);
    el('h3', 'Route changes and rejections', changes);
    if (!result.routes.length) el('p', 'No route changes or rejections logged.', changes);
    result.routes.forEach(line => el('p', describe(line), changes));
    const anchor = value.lines.find(l => l.type === 'route' && Number.isFinite(l.at_ms) && Number.isFinite(l.ts));
    const when = line => Number.isFinite(line.at_ms) ? `${fmtRunMs(line.at_ms)} run time` : anchor ? `≈ ${fmtRunMs((line.ts - anchor.ts) * 1000 + anchor.at_ms)} run time` : `${(line.ts - value.first_ts).toFixed(2)} s since first log entry`;
    // A log line keeps its element, so one the viewer opened stays open.
    const seen = new Map();
    const items = value.lines.map(line => { const text = JSON.stringify(line); const repeat = seen.get(text) || 0; seen.set(text, repeat + 1); return { line, id: `${text}\u0000${repeat}` }; });
    reconcile(list, items, item => item.id, ({ line }) => {
      const node = el('details', '', null); node.className = 'border-inspector-session';
      const head = el('summary', '', node);
      const dl = el('dl', '', node); dl.className = 'kv';
      for (const [key, value] of Object.entries(line)) { el('dt', words(key), dl); el('dd', typeof value === 'object' ? JSON.stringify(value) : words(value), dl); }
      return { node, head };
    }, (entry, { line }) => { entry.head.textContent = `${when(line)} · ${describe(line)}`; }, lines);
    aligned.hidden = !anchor;
  }, error => { status.textContent = `Could not read log lines: ${error.message}`; });
  return () => { stop(); root.replaceChildren(); };
}
