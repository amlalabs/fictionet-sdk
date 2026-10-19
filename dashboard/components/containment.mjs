import { scoped } from '../dom.mjs';

const labels = { contained: 'Contained', forwarded: 'Forwarded by the world', not_contained: 'Not contained', unknown: 'Not determined', missing_tool: 'Tool unavailable', timed_out: 'Timed out', fact: 'Configuration' };

export function mount(root, services, options) {
  const { el } = scoped(root);
  const status = el('p', { class: 'empty-note', role: 'status', text: 'No startup checks published yet.' }, root);
  const body = el('div', { class: 'containment-results' }, root);
  let snapshot, selected;
  function draw() {
    if (!snapshot) return;
    const guest = services.hosts?.find((host) => host.name === selected)?.sandbox || selected;
    const rows = (snapshot.value?.probes || []).filter((row) => !guest || row.guest === guest);
    const escaped = rows.filter((row) => row.outcome === 'not_contained').length;
    status.classList.toggle('containment-alert', escaped > 0);
    status.textContent = snapshot.status?.too_large ? 'Startup checks exceeded the state size limit. Results may be incomplete.'
      : escaped ? `${escaped} ${escaped === 1 ? 'probe got an answer' : 'probes got answers'} the world does not account for.`
      : rows.length ? 'Startup checks compare guest results with the world’s observations.' : 'No startup checks published yet.';
    body.replaceChildren();
    for (const row of rows) {
      const article = el('article', { class: 'containment-probe' }, body);
      const heading = el('h3', { text: `${!guest ? `${row.guest} · ` : ''}${row.name}` }, article);
      el('span', { class: row.outcome === 'contained' ? 'containment-ok' : 'egress-muted', text: labels[row.outcome] || row.outcome }, heading);
      el('code', { text: row.command }, article);
      el('p', { text: row.world_answer }, article);
      const details = el('details', {}, article);
      el('summary', { text: 'Guest result' }, details);
      el('pre', { text: row.guest_result }, details);
      for (const proxy of row.proxies || []) el('p', { text: `${proxy.name}: ${proxy.destination} (${proxy.world_host ? 'world host' : 'not a world host'})` }, article);
    }
  }
  const stopSelection = services.selection.subscribe(({ host }) => { selected = host; draw(); });
  const stopState = services.state(options.state, (value) => { snapshot = value; draw(); }, (error) => { status.textContent = `Could not load startup checks: ${error.message}`; });
  return () => { stopSelection(); stopState(); root.replaceChildren(); };
}
