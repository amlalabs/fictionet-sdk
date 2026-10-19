import { scoped, icon } from '../dom.mjs';

const labels = { contained: 'Contained', forwarded: 'Forwarded by the world', not_contained: 'Not contained', unknown: 'Not determined', missing_tool: 'Tool unavailable', timed_out: 'Timed out', fact: 'Configuration' };

export function guestResult(output = '') {
  const lines = output.split('\n').map((line) => line.trim()).filter(Boolean);
  const result = lines.find((line) => /^(HTTP(?:\/\S+)? \d{3}|curl:)|timed out|no servers could be reached/.test(line))
    || lines.find((line) => !line.startsWith(';') && !line.startsWith('%'));
  return result?.replace(/^;+\s*/, '') || 'No output';
}

export function mount(root, services, options) {
  const { el } = scoped(root);
  const status = el('p', { class: 'empty-note', role: 'status', text: 'No startup checks published yet.' }, root);
  const body = el('div', { class: 'containment-results' }, root);
  let snapshot, selected;
  function draw() {
    if (!snapshot) return;
    const guest = services.hosts?.find((host) => host.name === selected)?.sandbox || selected;
    const rows = (snapshot.value?.probes || []).filter((row) => !guest || row.guest === guest);
    const escaped = rows.filter((row) => row.outcome === 'not_contained');
    status.classList.toggle('containment-alert', escaped.length > 0);
    status.replaceChildren();
    for (const row of escaped) {
      const destination = row.command.match(/https?:\/\/[^\s'";]+/)?.[0] || row.destination;
      const alert = el('div', {}, status);
      icon(alert, 'warning');
      el('span', { text: `${row.guest} · ${row.name}: the guest got ${guestResult(row.guest_result)}${destination ? ` from ${destination}` : ''}, and the world has no record of it.` }, alert);
    }
    if (!escaped.length) status.textContent = snapshot.status?.too_large ? 'Startup checks exceeded the state size limit. Results may be incomplete.'
      : rows.length ? 'Startup checks compare guest results with the world’s observations.' : 'No startup checks published yet.';
    body.replaceChildren();
    const guests = [...new Set(rows.map((row) => row.guest))];
    for (const name of guests) {
      if (!guest) el('h3', { class: 'containment-guest', text: services.hosts?.find((host) => host.sandbox === name)?.name || name }, body);
      for (const row of rows.filter((row) => row.guest === name)) {
        const details = el('details', { class: `containment-probe ${row.outcome === 'not_contained' ? 'not-contained' : ''}` }, body);
        const summary = el('summary', {}, details);
        const title = el('span', { class: 'probe-title' }, summary);
        const name = el('strong', {}, title);
        icon(name, 'chevron');
        name.append(row.name);
        el('code', { class: 'probe-command', text: row.command, title: row.command }, title);
        el('span', { class: 'probe-result', text: guestResult(row.guest_result) }, summary);
        el('span', { class: 'probe-world', text: row.world_answer }, summary);
        const pill = el('span', { class: `outcome-pill ${row.outcome}` }, summary);
        icon(pill, row.outcome === 'contained' ? 'check' : row.outcome === 'not_contained' ? 'warning' : 'neutral');
        pill.append(labels[row.outcome] || row.outcome);
        if (row.outcome === 'forwarded') el('span', { class: 'mono', text: row.world_answer }, pill);
        const full = el('div', { class: 'probe-full' }, details);
        el('code', { text: row.command }, full);
        el('pre', { text: row.guest_result }, full);
        for (const proxy of row.proxies || []) el('p', { text: `${proxy.name}: ${proxy.destination} (${proxy.world_host ? 'world host' : 'not a world host'})` }, full);
      }
    }
  }
  const stopSelection = services.selection.subscribe(({ host }) => { selected = host; draw(); });
  const stopState = services.state(options.state, (value) => { snapshot = value; draw(); }, (error) => { status.textContent = `Could not load startup checks: ${error.message}`; });
  return () => { stopSelection(); stopState(); root.replaceChildren(); };
}
