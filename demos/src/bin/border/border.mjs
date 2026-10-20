// The routing workspace consumes the world's route state and bounded observations.
export function pathDiff(route, trace, destination) {
  const configured = [...(route?.bank_hops || []), destination];
  const observed = trace?.hops?.map(h => h.address) || [];
  return { configured, observed, beforeChange: !!trace && trace.started_ms < route.since_ms,
    matches: !!trace?.complete && configured.length === observed.length && configured.every((h, i) => h === observed[i]) };
}
function ip(text) {
  const parts = String(text).split('.');
  if (parts.length !== 4 || parts.some(p => !/^\d+$/.test(p) || Number(p) > 255)) return null;
  return parts.reduce((a, p) => (a * 256 + Number(p)) >>> 0, 0);
}
export function longestPrefix(routes, address) {
  const target = ip(address);
  if (target === null) return 'Invalid destination address.';
  const matches = routes.filter(route => {
    const [network, length] = route.prefix.split('/');
    const n = ip(network), bits = Number(length);
    if (n === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (target & mask) === (n & mask);
  }).sort((a, b) => Number(a.prefix.split('/')[1]) - Number(b.prefix.split('/')[1]));
  if (!matches.length) return `${address} has no matching route.`;
  const winner = matches.at(-1).prefix;
  if (matches.length === 1) return `${address} matches ${winner}; this route wins.`;
  return `${address} matches ${matches.map(r => r.prefix).join(' and ')}; the /${winner.split('/')[1]} is more specific, so it wins.`;
}
export function alertText(moment) { return moment.password ? 'The password reached the impostor' : 'A payment reached the impostor'; }
export function switchState(result) {
  if (!result || result.status === 'pending') return { busy: true, text: 'Waiting for the world…' };
  if (result.status === 'applied') return { busy: false, text: `Applied at revision ${result.reply.revision}.` };
  if (result.status === 'timeout') return { busy: false, text: 'No reply yet. The command may still apply. Check the current state before trying again.' };
  const r = result.rejection;
  if (r?.reason === 'stale_revision') return { busy: false, text: `Not applied: the route changed. Current revision ${r.current}. Check the state before trying again.` };
  return { busy: false, text: `Not applied: ${r?.message || result.error || 'the world is not taking commands right now.'}` };
}
// The guest link's last traceroute. A link that has closed keeps its last trace.
// `time` formats run milliseconds.
export function traceLines(link, diff, time) {
  const closed = link?.ended_ms == null ? '' : `guest link closed at ${time(link.ended_ms)}`;
  const trace = link?.trace;
  if (!trace) return { heading: closed ? `No UDP traceroute was observed; the ${closed}.` : 'No UDP traceroute observed on this guest link yet.' };
  return {
    heading: ['Last observed traceroute', time(trace.started_ms), trace.complete ? '' : 'incomplete', closed].filter(Boolean).join(' · '),
    hops: trace.hops.map(h => `${h.ttl} ${h.address}`).join(' → ') || (closed ? 'No replies arrived.' : 'Waiting for replies…'),
    note: diff.beforeChange ? 'The last traceroute ran before the change.'
      : diff.matches ? 'The observed path matches the current route.'
      : `The observed path does not ${closed ? '' : 'yet '}match the complete configured path.`,
  };
}

export function certificateField(key, value) {
  if (Array.isArray(value)) return value.join(', ');
  if (key === 'not_before' || key === 'not_after') {
    const match = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(value);
    if (match) { const [, year, month, day, hour, minute, second] = match; return `${year.length === 2 ? (Number(year) >= 50 ? '19' : '20') + year : year}-${month}-${day} ${hour}:${minute}:${second} UTC`; }
  }
  if (key === 'subject' || key === 'issuer') return value.replaceAll('2.5.4.3=', 'CN=');
  return value;
}

export function mount(root, services, options) {
  const { reconcile } = services.dom, { plural, fmtRunMs: time } = services.format;
  const { el } = services.dom.scoped(root);
  const css = el('link', {}, root); css.rel = 'stylesheet'; css.href = '/assets/border.css';
  root.classList.add('border-panel');
  const header = el('header', { class: 'border-heading' }, root);
  el('p', { class: 'eyebrow accent', text: 'KESTRELMOOR BANK · LIVE ROUTING' }, header);
  el('h1', { text: 'Kestrelmoor Bank, live routing' }, header);
  el('p', { class: 'border-deck', text: 'Hijacked makes Transpeak announce a more specific route to the bank’s network, so the guest’s packets for 84.21.44.10 reach an impostor.' }, header);
  const switchBox = el('section', { class: 'border-switch' }, root);
  const actions = el('div', { class: 'border-toggle' }, switchBox); actions.setAttribute('aria-label', 'Route mode');
  const stateLine = el('p', { class: 'mono', text: 'Waiting for routing state…' }, switchBox);
  const reply = el('p', { class: 'border-reply' }, switchBox); reply.setAttribute('role', 'status');
  el('p', { class: 'note', text: 'Routing commands do not claim browser input or pause the scripted agent.' }, switchBox);
  const error = el('p', { class: 'loss-note' }, root); error.setAttribute('role', 'status');
  const alert = el('section', { class: 'border-alert' }, root); alert.setAttribute('aria-live', 'polite'); alert.hidden = true;
  const pathBox = el('section', { class: 'section' }, root);
  el('h2', { text: 'Where the packets go' }, pathBox);
  const pathNote = el('p', { class: 'note' }, pathBox);
  const chain = el('ol', { class: 'border-path' }, pathBox);
  const traceBox = el('div', { class: 'border-trace' }, pathBox);
  const routeBox = el('section', { class: 'section' }, root); el('h2', { text: 'The route that wins' }, routeBox);
  const routes = el('div', {}, routeBox); const explanation = el('p', { class: 'note' }, routeBox);
  const bgpBox = el('details', {}, routeBox); el('summary', { text: 'What the BGP peer saw' }, bgpBox);
  const bgpEmpty = el('p', { class: 'note', text: 'No established BGP session observed yet.' }, bgpBox); const bgp = el('div', {}, bgpBox), bgpRows = new Map();
  const certBox = el('details', { class: 'section border-certificates' }, root);
  el('summary', { text: 'Certificates: the bank’s and the impostor’s' }, certBox);
  el('p', { class: 'note', text: 'The impostor’s leaf certificate names the same bank names.' }, certBox);
  const latest = el('p', { class: 'note', text: 'No observed TLS session yet.' }, certBox);
  const certs = el('div', { class: 'border-chains' }, certBox);
  const agent = el('section', { class: 'section' }, root); el('h2', { text: 'A scripted agent' }, agent);
  el('p', { text: 'Sign in → read balance → inspect certificate, traceroute and BGP → hold HTTPS open → flip route → inspect the failure → sign in with verification disabled → restore.' }, agent);
  el('p', { class: 'note', text: 'In the VM, the Terminal tab watches tmux session main. Ctrl-b d opens your login shell. Taking input does not pause the script.' }, agent);
  let route, view, pending = false, disposed = false, dismissed = 0, certValue, pathValue;
  const controller = new AbortController();
  const buttons = ['Normal', 'Hijacked'].map((label, index) => {
    const button = el('button', { text: label }, actions); button.type = 'button'; button.disabled = true;
    button.addEventListener('click', async () => {
      if (pending || !route || disposed) return;
      pending = true; reply.textContent = switchState().text; updateSwitch();
      let result;
      try { result = await services.transport.post('/api/command/routing', { request_id: crypto.randomUUID(), command: { mode: index ? 'hijack' : 'legitimate', expected_revision: route.revision } }, controller.signal); }
      catch (e) { result = e.body || { error: e.message }; }
      if (disposed) return;
      const state = switchState(result); pending = state.busy; reply.textContent = state.text; updateSwitch();
    }, { signal: controller.signal });
    return button;
  });
  function updateSwitch() {
    buttons.forEach((button, i) => { button.disabled = pending || !route; button.setAttribute('aria-pressed', String(route?.mode === (i ? 'hijack' : 'legitimate'))); });
    if (route) stateLine.textContent = `${route.mode === 'hijack' ? 'Hijacked' : 'Normal'} · revision ${route.revision} · changed ${time(Math.max(0, services.runTime() * 1000 - route.since_ms))} ago`;
    root.dataset.mode = route?.mode || 'loading';
  }
  function table(parent, headings, rows) {
    parent.replaceChildren(); const table = el('table', {}, parent); const head = el('tr', {}, el('thead', {}, table));
    headings.forEach(h => el('th', { text: h }, head)); const body = el('tbody', {}, table);
    rows.forEach(({ cells, mark }) => { const tr = el('tr', { class: mark ? 'border-winning' : '' }, body); cells.forEach(c => el('td', { text: String(c ?? '—') }, tr)); });
  }
  function render() {
    updateSwitch();
    if (!route || !view?.config) return;
    const config = view.config;
    const guestLink = view.links.find(l => l.sandbox === config.guest);
    const traced = guestLink?.trace;
    const diff = pathDiff(route, traced, config.bank);
    pathNote.textContent = `Configured round trip: ${route.mode === 'hijack' ? config.hijacked_ms : config.normal_ms} ms. This is the world's delay, not a latency measurement.`;
    const pathSignature = JSON.stringify([route.mode, diff.configured]);
    if (pathSignature !== pathValue) {
    pathValue = pathSignature; chain.replaceChildren();
    diff.configured.forEach((address, index) => {
      const country = config.countries.find(c => c.router === address) || config.countries[route.mode === 'hijack' && index === diff.configured.length - 1 ? 1 : 0];
      const li = el('li', { class: address === config.countries[1].router ? 'border-foreign' : '' }, chain);
      const last = index === diff.configured.length - 1;
      el('span', { class: 'border-hop-number', text: String(index + 1).padStart(2, '0') }, li);
      el('strong', { text: last ? (route.mode === 'hijack' ? 'Impostor' : 'Bank') : index === 0 ? 'Gateway' : country.name }, li);
      el('code', { text: last && route.mode === 'hijack' ? `${address}, the bank’s address` : address }, li);
      if (last && route.mode === 'hijack') el('code', { text: `machine ${config.impostor}` }, li);
      el('small', { text: `${country.name} · AS ${country.asn}` }, li);
    });
    }
    traceBox.replaceChildren();
    const lines = traceLines(guestLink, diff, time);
    if (!traced) el('p', { class: 'note', text: lines.heading }, traceBox);
    else {
      el('p', { text: lines.heading }, traceBox);
      el('p', { class: 'mono', text: lines.hops }, traceBox);
      el('p', { class: 'note', text: lines.note }, traceBox);
      if (traced.dropped) el('p', { class: 'loss-note', text: `Probes or hops dropped: ${traced.dropped}.` }, traceBox);
    }
    table(routes, ['Prefix', 'AS path', 'Origin'], route.routes.map(r => ({ cells: [r.prefix, r.as_path.join(' → '), `AS ${r.origin_as}`], mark: r.hijack })));
    explanation.textContent = longestPrefix(route.routes, config.bank);
    const seen = new Map();
    const events = view.bgp.rows.filter(b => b.sandbox === config.guest && (b.kind === 'established' || b.message === 'UPDATE' || b.message === 'NOTIFICATION'))
      .map(b => { const text = `${time(b.at_ms)} · ${b.kind} ${b.message} ${b.announced.length ? `announced ${b.announced.join(', ')}` : ''}${b.withdrawn.length ? `withdrawn ${b.withdrawn.join(', ')}` : ''} ${b.detail}`; const repeat = seen.get(text) || 0; seen.set(text, repeat + 1); return { text, id: `${text}\u0000${repeat}` }; });
    bgpEmpty.hidden = events.length > 0;
    reconcile(bgp, events, b => b.id, b => ({ node: el('p', { class: 'mono', text: b.text }, null) }), () => {}, bgpRows);
    const tls = view.tls.rows.filter(t => t.sandbox === config.guest).at(-1);
    if (tls) latest.textContent = `Most recent TLS session: ${tls.identity || 'unknown identity'} · ${tls.sni} · ${time(tls.at_ms)} · ${tls.outcome}. Answered by ${tls.endpoint.machine} at ${tls.endpoint.reached}.`;
    const signature = JSON.stringify(view.certificates);
    if (signature !== certValue) {
      certValue = signature; certs.replaceChildren();
      view.certificates.filter(c => c.identity !== 'status').forEach(c => {
        const column = el('article', {}, certs); column.dataset.identity = c.identity; el('h3', { text: c.identity === 'bank' ? 'The bank' : 'The impostor' }, column);
        el('p', { class: `border-trust ${c.trusted_issuer ? 'trusted' : 'untrusted'}`, text: c.trusted_issuer ? '✓ Issuer trusted by the guest' : '× Issuer not trusted by the guest' }, column);
        c.certificates.forEach((cert, i) => {
          el('h4', { text: i === 0 ? 'Leaf' : 'Issuer' }, column); const dl = el('dl', {}, column);
          for (const [key, value] of Object.entries(cert)) { el('dt', { text: key.replaceAll('_', ' ') }, dl); el('dd', { text: certificateField(key, value) }, dl); }
        });
      });
    }
    for (const column of certs.children) column.dataset.latest = String(column.dataset.identity === tls?.identity);
    const moment = view.moments.rows.at(-1);
    alert.hidden = !moment || moment.event <= dismissed;
    if (!alert.hidden && alert.dataset.event !== String(moment.event)) {
      alert.dataset.event = String(moment.event); alert.replaceChildren(); el('h2', { text: alertText(moment) }, alert);
      el('p', { class: 'mono', text: `${time(moment.at_ms)} · ${moment.method} ${moment.path} · connection ${moment.connection ?? 'unknown'} · ${moment.endpoint.machine} at ${moment.endpoint.reached} · ${plural(view.moments.rows.length + view.moments.dropped, 'moment')}` }, alert);
      if (moment.payee != null || moment.amount_pence != null) el('p', { text: `Payee: ${moment.payee ?? 'not reported'} · amount: ${moment.amount_pence ?? 'not reported'} pence` }, alert);
      const buttons = el('div', { class: 'border-alert-actions' }, alert);
      const select = (label, kind) => { const button = el('button', { class: 'button', text: label }, buttons); button.type = 'button'; button.onclick = () => { services.selection.set({ host: moment.sandbox, event: { seq: moment.event }, connection: moment.connection, links: [] }); services.showPanel(kind); }; };
      select('Select request event', 'events');
      if (moment.peer && moment.port) {
        const flow = el('button', { class: 'button', text: 'Show matching flow (approximate)' }, buttons); flow.type = 'button';
        flow.onclick = () => { services.selection.set({ host: moment.sandbox, event: { seq: moment.event }, connection: moment.connection, links: [] }); services.showPackets({ local: `${moment.endpoint.reached}:${moment.port}`, peer: moment.peer }); };
      }
      el('p', { class: 'note', text: 'The event uses its exact connection identity. Packet matching uses the guest-visible addresses and ports and is approximate.' }, alert);
      const dismiss = el('button', { class: 'button', text: 'Dismiss alert' }, buttons); dismiss.type = 'button'; dismiss.onclick = () => { dismissed = moment.event; alert.hidden = true; };
    }
    const dropped = view.lost + view.truncated + view.bgp.dropped + view.tls.dropped + view.moments.dropped;
    error.textContent = dropped ? `Limited history: observations lost: ${view.lost}, fields truncated: ${view.truncated}; older rows dropped: BGP ${view.bgp.dropped}, TLS ${view.tls.dropped}, moments ${view.moments.dropped}.` : '';
  }
  const failed = e => { error.textContent = `Could not read state: ${e.message}`; };
  const cleanup = [services.state('/api/state/routing', s => { route = s.value; render(); }, failed), services.state(options.state, s => { view = s.value; render(); if (s.status?.too_large) error.textContent = 'The projection exceeded its byte limit; this snapshot may be stale.'; }, failed)];
  const timer = setInterval(updateSwitch, 1000);
  return () => { disposed = true; controller.abort(); clearInterval(timer); cleanup.forEach(stop => stop()); root.replaceChildren(); root.classList.remove('border-panel'); };
}
