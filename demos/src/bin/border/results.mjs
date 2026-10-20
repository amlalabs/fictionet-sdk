const words = value => String(value).replaceAll('_', ' ');
const count = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
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
  const el = (tag, text, parent = root) => { const n = root.ownerDocument.createElement(tag); n.textContent = text; parent.append(n); return n; };
  const css = el('link', ''); css.rel = 'stylesheet'; css.href = '/assets/border.css';
  el('h2', 'From the world’s log');
  el('p', 'The log for this run, which the eval’s scorer reads. Counts cover the retained lines below.');
  const status = el('p', 'Waiting for log lines…');
  const summary = el('div', ''); summary.className = 'border-inspector-summary';
  const changes = el('div', ''); const rows = el('div', '');
  const stop = services.state(options.state, ({ value, status: state }) => {
    if (!value) return;
    status.textContent = `${count(value.lines.length, 'retained line')} · dropped: ${value.dropped} · unreadable: ${value.invalid}${state?.too_large ? ' · publication exceeded its limit' : ''}`;
    const result = summarize(value.lines); summary.replaceChildren(); changes.replaceChildren();
    for (const text of [`Bank: ${count(result.bank, 'TLS session')}`, `Impostor: ${count(result.impostor, 'TLS session')}`, `Client aborted: ${count(result.aborted, 'TLS session')}`, `Impostor answered: ${count(result.requests, 'request')}`, `Password reached impostor: ${result.passwords ? 'yes' : 'no'} (${result.passwords})`, `Payment reached impostor: ${result.payments ? 'yes' : 'no'} (${result.payments})`]) el('p', text, summary);
    el('h3', 'Route changes and rejections', changes);
    if (!result.routes.length) el('p', 'No route changes or rejections logged.', changes);
    result.routes.forEach(line => el('p', describe(line), changes));
    rows.replaceChildren(); el('h3', 'In time order', rows);
    const anchor = value.lines.find(l => l.type === 'route' && Number.isFinite(l.at_ms) && Number.isFinite(l.ts));
    for (const line of value.lines) {
      const item = el('details', '', rows); item.className = 'border-inspector-session';
      const time = Number.isFinite(line.at_ms) ? `${(line.at_ms / 1000).toFixed(2)} s run time` : anchor ? `≈ ${(line.ts - anchor.ts + anchor.at_ms / 1000).toFixed(2)} s run time` : `${(line.ts - value.first_ts).toFixed(2)} s since first log entry`;
      el('summary', `${time} · ${describe(line)}`, item);
      const dl = el('dl', '', item); dl.className = 'kv';
      for (const [key, value] of Object.entries(line)) { el('dt', words(key), dl); el('dd', typeof value === 'object' ? JSON.stringify(value) : words(value), dl); }
    }
    if (anchor) el('p', 'Approximate run times align log timestamps to the route change’s recorded run time.', rows);
  }, error => { status.textContent = `Could not read log lines: ${error.message}`; });
  return () => { stop(); root.replaceChildren(); };
}
