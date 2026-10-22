const $ = (id) => document.getElementById(id);
const element = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};
const button = (text, action, className) => {
  const node = element('button', text, className);
  node.type = 'button';
  node.addEventListener('click', action);
  return node;
};
const time = (ms) => `${String(Math.floor(ms / 60000)).padStart(2, '0')}:${String(Math.floor(ms / 1000) % 60).padStart(2, '0')}`;
const stamp = (ms) => (ms / 1000).toFixed(3);
const size = (bytes) => bytes < 1024 ? `${bytes} B` : `${Math.round(bytes / 1024)} KB`;
const sourceName = (source) => source.kind === 'copy' ? source.captured ? `copy captured ${source.captured.slice(0, 10)}` : 'copy · capture date unavailable' : source.kind === 'live' ? 'live' : 'model-written';
const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };
let latest = { at_ms: 0, oldest_ms: 0, sites: [], calls: [], activity: [] };
let shown = latest, selection = null, live = true, world = null;
let rewindRequest, noticeTimer, activeConsole = 'terminal', input = false, hostStatus = null;
const consoles = new Map();
const mounting = new Set();
const socketUrl = (path) => `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/${path}`;
history.replaceState(null, '', '/');
function notice(text) {
  $('notice').textContent = text;
  $('notice').hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { $('notice').hidden = true; }, 6500);
}
function select(key) {
  selection = key;
  $('details').hidden = !key;
  document.body.classList.toggle('details-open', !!key);
  $('agent').hidden = !!key; $('agent-toggle').setAttribute('aria-pressed', String(!key));
  draw();
}
$('close-details').onclick = () => select(null);
$('agent-toggle').onclick = () => {
  if (selection) { select(null); return; }
  $('agent').hidden = !$('agent').hidden;
  $('agent-toggle').setAttribute('aria-pressed', String(!$('agent').hidden));
};
function svg(tag, attrs = {}, text) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  if (text !== undefined) node.textContent = text;
  return node;
}
function graph() {
  const map = $('map');
  map.replaceChildren();
  map.append(svg('rect', { x: 20, y: 262, width: 155, height: 136, rx: 16, fill: 'none', stroke: '#252e42', 'stroke-dasharray': '3 5' }), svg('rect', { x: 200, y: 20, width: 560, height: 620, rx: 22, fill: '#0d1426', 'fill-opacity': '.6', stroke: '#1e3361' }), svg('rect', { x: 790, y: 262, width: 188, height: 136, rx: 16, fill: '#140e0b', stroke: '#4d2c16' }));
  map.append(svg('text', { x: 36, y: 287, class: 'map-label' }, 'VM'), svg('text', { x: 220, y: 45, class: 'map-label', style: 'fill:#5b86d9' }, 'THE WORLD'), svg('text', { x: 806, y: 287, class: 'map-label', style: 'fill:#c9814f' }, 'INTERNET'));
  const wire = (path, kind = '') => map.append(svg('path', { d: path, class: `wire ${kind}` }));
  const node = (id, x, y, width, title, address, outside = false, active = false) => {
    const group = svg('g', { class: `node ${selection === id ? 'selected' : ''} ${outside ? 'outside' : ''} ${active ? 'active' : ''}`, role: 'button', tabindex: '0', 'aria-label': title, 'aria-pressed': String(selection === id) });
    group.append(svg('title', {}, `${title}${address ? ` · ${address}` : ''}`), svg('rect', { x, y, width, height: 48, rx: 11 }));
    group.append(svg('text', { x: x + 12, y: y + (address ? 20 : 29) }, title.length > 27 ? `${title.slice(0, 25)}…` : title));
    if (address) group.append(svg('text', { x: x + 12, y: y + 36, class: 'address' }, address));
    group.addEventListener('click', () => select(id));
    group.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(id); } });
    map.append(group);
  };
  wire('M160 330 L248 330', shown.activity.length ? 'hot' : '');
  wire('M360 330 L580 330 M718 330 L800 330', shown.calls.length ? 'outside hot' : 'outside');
  node('workstation', 32, 306, 128, 'workstation', hostStatus?.addresses[0] || '10.0.0.2', false, true);
  node('router', 248, 306, 112, 'router', '10.0.0.1', false, true);
  node('calls', 580, 306, 138, 'model gateway', '', true);
  const provider = shown.calls.at(-1)?.host;
  node('calls', 800, 306, 167, provider || 'Model provider', provider ? '' : 'No calls yet', true);
  const rows = [{ host: 'DNS', address: '10.0.0.1:53', at_ms: shown.activity.filter((r) => r.fact.kind === 'resolved').at(-1)?.at_ms ?? 0 }];
  const all = [...shown.sites].sort((a, b) => b.at_ms - a.at_ms);
  const visible = all.slice(0, 7);
  if (selection?.startsWith('site:')) {
    const selected = all.find((s) => `site:${s.host}` === selection);
    if (selected && !visible.includes(selected)) visible.splice(-1, 1, selected);
  }
  rows.push(...visible);
  const positions = [56, 116, 176, 236, 424, 484, 544, 604];
  rows.forEach((site, i) => {
    const y = positions[i];
    const active = shown.activity.at(-1)?.at_ms === site.at_ms && (live || selection === `site:${site.host}`);
    wire(`M360 330 C410 330,420 ${y},480 ${y}`, active ? 'hot' : '');
    node(site.host === 'DNS' ? 'dns' : `site:${site.host}`, 480, y - 24, 238, site.host, String(site.address || ''), false, active);
  });
  const refusal = shown.activity.filter((r) => r.fact.kind === 'no_route').at(-1);
  if (refusal) {
    wire('M304 354 C304 440,266 518,250 560', 'no-route');
    map.append(svg('circle', { cx: 250, cy: 570, r: 10, fill: '#1a1016', stroke: '#7a3a4a' }), svg('path', { d: 'M246 566 L254 574 M254 566 L246 574', stroke: '#f2a7b4', 'stroke-width': 1.6 }), svg('text', { x: 268, y: 568, style: 'fill:#e6a3b0;font:12px monospace' }, refusal.fact.to), svg('text', { x: 268, y: 586, style: 'fill:#6b768a;font:11px sans-serif' }, 'no route'));
  }
  if (all.length > 7) {
    const more = svg('g', { class: 'node', role: 'button', tabindex: '0', 'aria-label': 'All sites' });
    more.append(svg('text', { x: 730, y: 620, style: 'fill:#7fb0ff;font:11px sans-serif' }, 'All sites ›'));
    more.onclick = () => select('sites'); more.onkeydown = (e) => { if (e.key === 'Enter') select('sites'); };
    map.append(more);
  }
  $('empty').hidden = !!shown.activity.length;
}
function activityText(row) {
  const fact = row.fact;
  switch (fact.kind) {
    case 'resolved': return [fact.name, 'DNS', `${fact.name} → ${fact.address || 'no answer'}`, `site:${fact.name}`];
    case 'request': return [fact.host, 'HTTP', `${fact.method} ${fact.path} · ${fact.status}`, `site:${fact.host}`];
    case 'search': return [{google:'www.google.com',bing:'www.bing.com',duck_duck_go:'html.duckduckgo.com',you_tube:'www.youtube.com'}[fact.engine] || 'Search', 'Search', fact.query, 'sites'];
    case 'model_call': return [fact.host, 'HTTPS', `${fact.method} ${fact.path} · ${fact.status || 'connecting'}${fact.phase === 'streaming' ? ' · streaming' : ''}`, 'calls'];
    case 'tool': return ['model gateway', 'Tool', `${fact.tool === 'fetch' ? 'Fetch' : 'web_search'} · ${fact.target}`, 'calls'];
    case 'no_route': return [fact.to, 'TCP', 'no route', 'router'];
    default: return ['', '', '', 'router'];
  }
}
function feed() {
  $('activity').replaceChildren();
  for (const row of shown.activity.slice(-5)) {
    const [target, protocol, text, selected] = activityText(row);
    const item = button('', () => select(selected), `activity-row ${row.fact.kind}`);
    item.append(element('span', stamp(row.at_ms), 'stamp'), element('span', target), element('span', protocol), element('span', text));
    $('activity').append(item);
  }
  if (world?.preview) {
    $('preview-output').textContent = shown.activity.slice(-10).map((r) => { const [host, protocol, text] = activityText(r); return `${protocol}  ${host}\n  ${text}`; }).join('\n\n');
  }
}
function detailRow(at, label, meta, content) {
  const row = element('div', undefined, 'detail-row');
  row.append(element('span', stamp(at), 'stamp'));
  const body = element('div');
  body.append(element('div', label, 'label'));
  if (meta) body.append(element('div', meta, 'meta'));
  if (content) body.append(content);
  row.append(body);
  return row;
}
function results(hits) {
  const list = element('div');
  const add = (hit) => {
    const row = element('div', undefined, 'result'), link = element('a', hit.title || hit.url);
    link.href = '#';
    link.onclick = (event) => { event.preventDefault(); select(`site:${hostOf(hit.url)}`); };
    row.append(link, element('small', hostOf(hit.url))); list.append(row);
  };
  hits.slice(0, 4).forEach(add);
  if (hits.length > 4) list.append(button(`${hits.length - 4} more`, (event) => { event.currentTarget.remove(); hits.slice(4).forEach(add); }, 'more'));
  return list;
}
function details() {
  if (!selection) return;
  const body = $('detail-body'), actions = $('detail-actions');
  body.replaceChildren(); actions.replaceChildren();
  const heading = (title, subtitle = '') => { $('detail-title').textContent = title; $('detail-subtitle').textContent = subtitle; };
  if (selection === 'calls') {
    heading('Model calls', [...new Set(shown.calls.map((c) => c.host))].join(' · ') || 'Through the world’s model gateway');
    if (!shown.calls.length) body.append(element('p', 'No model calls yet. Calls appear here when an agent uses its provider.', 'detail-empty'));
    for (const call of shown.calls) {
      const content = element('details');
      content.open = call.tools.length > 0 || !['complete','interrupted'].includes(call.phase);
      const summary = element('summary');
      summary.append(element('div', `${call.method} ${call.path}`, 'label'), element('div', call.phase === 'streaming' ? 'streaming' : call.phase === 'interrupted' ? `${call.status || ''} · interrupted` : call.status ? `${call.status}${call.phase === 'complete' ? '' : ' · receiving'}` : 'connecting', call.phase === 'streaming' ? 'meta streaming' : 'meta'));
      content.append(summary);
      for (const tool of call.tools) {
        content.append(element('p', `tool use: ${tool.tool === 'fetch' ? 'Fetch' : 'web_search'}`, 'meta'), element('p', tool.target, 'tool-query'));
        content.append(element('p', tool.error || (tool.tool === 'fetch' ? 'Answered by the world' : `Answered by the world · ${tool.results.length} result${tool.results.length === 1 ? '' : 's'}`), 'world-answer'));
        content.append(results(tool.results));
      }
      const row = element('div', undefined, 'detail-row'); row.append(element('span', stamp(call.at_ms), 'stamp'), content); body.append(row);
    }
  } else if (selection.startsWith('site:')) {
    const name = selection.slice(5), site = shown.sites.find((s) => s.host === name);
    const last = site?.requests.at(-1);
    heading(name, [site?.address, last && sourceName(last.source)].filter(Boolean).join(' · '));
    for (const event of shown.activity.filter((row) => row.fact.kind === 'resolved' && row.fact.name === name)) body.append(detailRow(event.at_ms, 'DNS', `${name} → ${event.fact.address || 'no answer'}`));
    for (const search of site?.searches || []) {
      const content = element('div'); content.append(element('p', `“${search.query}”`, 'tool-query'), results(search.results));
      body.append(detailRow(search.at_ms, 'Search', `${search.results.length} results`, content));
    }
    for (const request of site?.requests || []) {
      const content = element('details'), summary = element('summary'), data = element('dl');
      summary.append(element('div', `${request.method} ${request.path}`, 'label'), element('div', `${request.status} · ${request.content_type.split(';')[0]} · ${size(request.bytes)} · ${request.elapsed_ms} ms`, 'meta'));
      for (const [key, value] of [...request.headers, ['served by', sourceName(request.source)]]) data.append(element('dt', key), element('dd', value));
      content.append(summary, data);
      const row = element('div', undefined, 'detail-row'); row.append(element('span', stamp(request.at_ms), 'stamp'), content); body.append(row);
    }
    if (!site?.requests.length && !site?.searches.length) body.append(element('p', site ? 'No page requests at this point in the run.' : 'This site has not been opened at this point in the run.', 'detail-empty'));
    const recorded = [...(site?.requests || [])].reverse().find((r) => r.has_preview);
    if (recorded) actions.append(button('Page', async (event) => {
      event.currentTarget.disabled = true;
      try {
        const query = new URLSearchParams({ host: name, path: recorded.path, at_ms: recorded.at_ms });
        const response = await fetch(`/preview?${query}`);
        if (!response.ok) throw new Error(await response.text());
        const markup = await response.text();
        $('page-title').textContent = `${name}${recorded.path}`;
        // Recorded markup stays inert inside the sandbox.
        $('page-preview').srcdoc = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">${markup}`;
        $('page-dialog').showModal();
      } catch (error) { notice(error.message); }
      finally { const pageButton = $('detail-actions').querySelector('button'); if (pageButton) pageButton.disabled = false; }
    }));
  } else if (selection === 'sites') {
    heading('Sites', 'Visited by the workstation');
    for (const site of shown.sites) {
      const row = button(site.host, () => select(`site:${site.host}`), 'site-list'); row.append(element('small', site.address || 'World search')); body.append(row);
    }
    if (!shown.sites.length) body.append(element('p', 'No sites yet.', 'detail-empty'));
  } else if (selection === 'dns') {
    heading('DNS', '10.0.0.1:53');
    for (const row of shown.activity.filter((row) => row.fact.kind === 'resolved')) body.append(detailRow(row.at_ms, row.fact.name, row.fact.address || 'no answer'));
  } else if (selection === 'router') {
    heading('Router', '10.0.0.1');
    for (const row of shown.activity.filter((row) => row.fact.kind === 'no_route')) body.append(detailRow(row.at_ms, row.fact.to, 'no route'));
    if (!body.children.length) body.append(element('p', 'Routes connect the workstation to services in the world.', 'detail-empty'));
  } else {
    heading('Workstation', hostStatus?.addresses.join(' · ') || '10.0.0.2');
    body.append(element('p', world?.preview ? 'No VM is running. The preview client makes real requests inside the world.' : 'Ubuntu desktop with Firefox, Claude Code and Codex.', 'detail-empty'));
    actions.append(button('Show agent', () => { select(null); $('agent').hidden = false; $('agent-toggle').setAttribute('aria-pressed', 'true'); }));
  }
}
function draw() {
  graph(); feed(); details();
  $('clock').textContent = time(latest.at_ms);
  $('cursor-time').textContent = time(shown.at_ms);
  $('end-time').textContent = time(latest.at_ms);
  $('oldest').textContent = `${time(latest.oldest_ms)}${latest.oldest_ms ? ' retained' : ' boot'}`;
  $('scrubber').min = latest.oldest_ms;
  $('scrubber').max = Math.max(latest.at_ms, latest.oldest_ms);
  $('scrubber').value = shown.at_ms;
  $('live').classList.toggle('active', live);
  $('play').textContent = live ? 'Ⅱ' : '▶';
  $('play').setAttribute('aria-label', live ? 'Pause observation' : 'Return to live observation');
  $('rewind-label').hidden = live;
}
async function rewind(at) {
  live = false;
  rewindRequest?.abort();
  rewindRequest = new AbortController();
  try {
    const reply = await fetch(`/view?at_ms=${at}`, { signal: rewindRequest.signal });
    if (!reply.ok) throw new Error('Could not load this point in the run');
    shown = await reply.json(); draw();
  } catch (error) { if (error.name !== 'AbortError') notice(error.message); }
}
$('scrubber').addEventListener('input', (event) => rewind(Number(event.target.value)));
function goLive() { rewindRequest?.abort(); live = true; shown = latest; draw(); }
$('live').onclick = goLive;
$('play').onclick = () => live ? rewind(shown.at_ms) : goLive();
const stream = new EventSource('/state');
stream.onopen = () => { $('connection').classList.add('connected'); $('connection').title = 'Connected'; };
stream.onerror = () => { $('connection').classList.remove('connected'); $('connection').title = 'Reconnecting'; };
stream.onmessage = (event) => {
  latest = JSON.parse(event.data);
  if (live || shown.at_ms < latest.oldest_ms) { shown = latest; live = true; }
  draw();
};
async function loadWorld() {
  const response = await fetch('/world');
  if (!response.ok) throw new Error('Could not read the world settings');
  world = await response.json();
  $('preview-label').hidden = !world.preview;
  $('world-date').textContent = world.date;
  $('brief').textContent = world.instructions;
  $('source').value = world.source.kind === 'copy' ? 'copied' : world.source.kind === 'live' ? 'live' : 'model_written';
  for (const option of $('source').options) {
    option.disabled = !world[option.value];
    const text = { copied: 'Copied pages', model_written: 'Model-written pages', live: 'Live search' }[option.value];
    option.textContent = `${text}${option.disabled ? option.value === 'copied' ? ' · corpus unavailable' : option.value === 'live' ? ' · needs EXA_API_KEY' : ' · needs OPENROUTER_API_KEY' : ''}`;
  }
  $('source-help').textContent = world.source.kind === 'copy' ? 'The copied corpus, served at its original URLs.' : world.source.kind === 'live' ? 'Searches and captures come from the internet.' : 'Pages are written from the world brief.';
  if (world.preview) {
    $('console-status').hidden = true;
    $('terminal').hidden = true; $('screen').hidden = true;
    $('preview-console').hidden = false;
    $('terminal-tab').disabled = true; $('screen-tab').disabled = true;
    $('input-toggle').hidden = true; $('input-status').hidden = true;
    $('host-status').textContent = 'In-world client · no VM';
    draw();
  }
}
$('world-toggle').onclick = () => { $('world-menu').hidden = !$('world-menu').hidden; $('world-toggle').setAttribute('aria-expanded', String(!$('world-menu').hidden)); };
document.addEventListener('click', (event) => { if (!$('world-menu').contains(event.target) && !$('world-toggle').contains(event.target)) { $('world-menu').hidden = true; $('world-toggle').setAttribute('aria-expanded', 'false'); } });
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { $('world-menu').hidden = true; $('world-toggle').setAttribute('aria-expanded', 'false'); select(null); } });
async function command(command) {
  $('world-error').textContent = '';
  const response = await fetch('/command', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(command) });
  if (!response.ok) throw new Error(await response.text());
  await loadWorld();
}
$('source').onchange = async () => { $('source').disabled = true; try { await command({ command: 'set_source', source: $('source').value }); } catch (error) { $('world-error').textContent = error.message; await loadWorld(); } finally { $('source').disabled = false; } };
$('restart').onclick = async () => { $('restart').disabled = true; try { await command({ command: 'restart' }); select(null); goLive(); } catch (error) { $('world-error').textContent = error.message; } finally { $('restart').disabled = false; } };
$('close-page').onclick = () => { $('page-dialog').close(); $('page-preview').srcdoc = ''; };
$('story').onclick = async () => {
  $('story').disabled = true;
  try { const response = await fetch('/story', { method: 'POST' }); if (!response.ok) throw new Error(await response.text()); }
  catch (error) { notice(error.message); }
  finally { $('story').disabled = false; }
};
async function mountConsole() {
  if (world?.preview || !hostStatus) return;
  const kind = activeConsole;
  $('terminal').hidden = kind !== 'terminal'; $('screen').hidden = kind !== 'screen';
  $('terminal-tab').setAttribute('aria-pressed', String(kind === 'terminal'));
  $('screen-tab').setAttribute('aria-pressed', String(kind === 'screen'));
  const ready = kind === 'screen' ? hostStatus.screen : hostStatus.terminal;
  $('console-status').hidden = ready;
  $('console-status').textContent = hostStatus.state === 'failed' ? 'The workstation failed to start. See the process output.' : hostStatus.state === 'stopped' ? 'The workstation has stopped.' : 'Waiting for the workstation…';
  if (!ready || mounting.has(kind)) return;
  const existing = consoles.get(kind);
  if (existing && existing.socket.readyState <= 1) { existing.component.setInput(input); return; }
  existing?.component.dispose();
  mounting.add(kind);
  let socket;
  try {
    let create;
    if (kind === 'terminal') {
      const [library, component] = await Promise.all([import('/vendor/ghostty-web/dist/ghostty-web.js'), import('/terminal.mjs')]);
      await library.init();
      create = (socket) => component.mount($('terminal'), library, socket, { fontSize: 13, fontFamily: 'monospace', disableStdin: !input, theme: { background: '#0b0f18', foreground: '#d6dee8', cursor: '#9dbdf5' } });
    } else {
      const [{ default: RFB }, component] = await Promise.all([import('/vendor/novnc/core/rfb.js'), import('/screen.mjs')]);
      create = (socket) => component.mount($('screen'), RFB, socket, input);
    }
    socket = new WebSocket(socketUrl(kind));
    socket.addEventListener('close', () => { if (activeConsole === kind) { $('console-status').hidden = false; $('console-status').textContent = 'Console disconnected. Select Terminal or Screen to reconnect.'; } });
    socket.addEventListener('error', () => notice('Could not connect to the workstation console'));
    $(kind).replaceChildren();
    const component = create(socket);
    component.setInput(input);
    consoles.set(kind, { component, socket });
  } catch (error) { socket?.close(); notice(`Console unavailable: ${error.message}`); }
  finally { mounting.delete(kind); }
}
$('terminal-tab').onclick = () => { activeConsole = 'terminal'; mountConsole(); };
$('screen-tab').onclick = () => { activeConsole = 'screen'; mountConsole(); };
$('input-toggle').onclick = () => {
  input = !input; $('input-status').textContent = input ? 'Input on' : 'Input off'; $('input-toggle').textContent = input ? 'Disable input' : 'Enable input';
  for (const console of consoles.values()) console.component.setInput(input);
};
const status = new EventSource('/host/state');
status.onmessage = (event) => {
  const next = JSON.parse(event.data);
  const changed = JSON.stringify(next) !== JSON.stringify(hostStatus);
  hostStatus = next;
  if (!world?.preview) { $('host-status').textContent = { booting: 'Booting', network_up: 'Network up', ssh_up: 'SSH ready', desktop_up: 'Desktop ready', stopped: 'Stopped', failed: 'Failed' }[next.state] || next.state; if (changed) mountConsole(); }
};
loadWorld().then(() => { if (!world.preview) mountConsole(); }).catch((error) => notice(error.message));
draw();
window.addEventListener('pagehide', () => { stream.close(); status.close(); for (const console of consoles.values()) { console.component.dispose(); console.socket.close(); } rewindRequest?.abort(); });
