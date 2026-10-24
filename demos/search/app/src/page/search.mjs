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
const stamp = (ms) => new Date((shown.started_at_ms || Date.now()) + ms).toLocaleTimeString([], { hour12: false });
const time = stamp;
const size = (bytes) => bytes < 1024 ? `${bytes} B` : `${Math.round(bytes / 1024)} KB`;
const sourceName = (source) => source.kind === 'copy' ? source.captured ? `Copied · ${source.captured.slice(0, 10)}` : 'Copied' : source.kind === 'live' ? 'live' : 'model-written';
const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };
let latest = { at_ms: 0, oldest_ms: 0, sites: [], calls: [], activity: [], connections: [], egress: [], signin: null };
let shown = latest, selection = null, live = true, world = null;
let rewindRequest, noticeTimer, activeConsole = 'terminal', hostStatus = null, fontSize = 19;
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
  if (key !== selection) document.body.classList.remove('page-expanded');
  document.body.classList.toggle('page-selected', !!key?.startsWith('page:'));
  selection = key;
  $('details').hidden = !key;
  document.body.classList.toggle('details-open', !!key);
  if (key) { $('agent').hidden = false; $('agent-toggle').setAttribute('aria-pressed', 'true'); }
  draw();
}
$('close-details').onclick = () => select(null);
$('agent-size').onclick = () => {
  const expanded = document.body.classList.toggle('agent-expanded');
  $('agent-size').setAttribute('aria-pressed', String(expanded));
  $('agent-size').setAttribute('aria-label', expanded ? 'Shrink agent' : 'Expand agent');
};
$('agent-toggle').onclick = () => {
  $('agent').hidden = !$('agent').hidden;
  $('agent-toggle').setAttribute('aria-pressed', String(!$('agent').hidden));
};
function svg(tag, attrs = {}, text) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  if (text !== undefined) node.textContent = text;
  return node;
}
function localSites() {
  const upstream = new Set([...shown.connections.map((row) => row.host), ...shown.calls.map((call) => call.host)]);
  return shown.sites.filter((site) => !upstream.has(site.host));
}

function graph(upstream, newData) {
  const map = $('map'), width = Math.min(map.clientWidth, 760), height = map.clientHeight;
  $('world').classList.toggle('world-compact', map.clientWidth < 820);
  map.replaceChildren();
  if (!width || !height) return;
  map.setAttribute('viewBox', `0 0 ${width} ${height}`);
  const destinations = [...new Set(shown.connections.map((row) => row.host))];
  const top = 76, internet = height - (destinations.length ? 106 : 80), bottom = internet - 12;
  map.append(svg('rect', { x: 14, y: 10, width: 212, height: 56, rx: 14, class: 'vm-zone' }), svg('rect', { x: 14, y: top, width: width - 28, height: bottom - top, rx: 16, class: 'world-zone' }), svg('rect', { x: 14, y: internet, width: width - 28, height: height - internet - 12, rx: 14, class: 'internet-zone' }));
  map.append(svg('text', { x: 24, y: 43, class: 'map-label' }, 'VM'), svg('text', { x: 26, y: top + 23, class: 'map-label world-label' }, 'THE WORLD'));
  const wires = svg('g'); map.append(wires);
  const wire = (path, kind = '', pulse = false) => {
    wires.append(svg('path', { d: path, class: `wire ${kind}` }));
    if (pulse && live) {
      const dot = svg('circle', { r: 3, class: `packet ${kind}` });
      dot.append(svg('animateMotion', { path, dur: '1.2s', repeatCount: '1', fill: 'freeze' }));
      wires.append(dot);
    }
  };
  const node = (id, x, y, w, h, title, address = '', outside = false) => {
    const group = svg('g', { class: `node ${selection === id ? 'selected' : ''} ${outside ? 'outside' : ''}`, role: 'button', tabindex: '0', 'aria-label': title, 'aria-pressed': String(selection === id) });
    group.append(svg('title', {}, [title, address].filter(Boolean).join(' · ')), svg('rect', { x, y, width: w, height: h, rx: 8 }));
    const subtitle = h >= 36 && address;
    const limit = Math.floor((w - 22) / 7.5);
    const label = title.length > limit ? `${title.slice(0, limit - 1)}…` : title;
    group.append(svg('text', { x: x + 10, y: y + (subtitle ? 16 : h / 2 + 4) }, label));
    if (subtitle) group.append(svg('text', { x: x + 10, y: y + 31, class: 'address' }, address.length > limit ? `${address.slice(0, limit - 1)}…` : address));
    group.onclick = () => select(id);
    group.onkeydown = (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(id); } };
    map.append(group);
  };
  const sites = localSites().sort((a, b) => b.at_ms - a.at_ms);
  const count = Math.max(0, Math.min(3, Math.floor((bottom - top - 34) / 44) - 4));
  const visible = sites.slice(0, count);
  const selectedHost = selection?.startsWith('site:') ? selection.slice(5) : selection?.startsWith('page:') ? hostOf(selection.slice(5)) : null;
  const selected = sites.find((site) => site.host === selectedHost);
  if (selected && !visible.includes(selected)) visible.splice(Math.max(0, count - 1), 1, selected);
  const services = [{ id: 'dns', title: 'DNS', address: '10.0.0.1:53' }, ...visible.map((site) => ({ id: `site:${site.host}`, title: site.host, address: site.address || '' })), { id: 'sites', title: 'All sites ›' }, { id: 'calls', title: 'model gateway' }, { id: 'signin', title: 'sign-in', address: shown.signin ? shown.signin.fact.open ? 'Open' : 'Closed' : '' }];
  const step = Math.min(48, (bottom - top - 34) / services.length), nodeHeight = step - 6;
  const first = top + 30, routerY = (top + bottom) / 2 - 4;
  wire(`M139 58 V${routerY + 20}`, shown.activity.length ? 'hot' : '');
  node('workstation', 64, 18, 150, 40, 'workstation', hostStatus?.addresses[0] || '10.0.0.2');
  node('router', 30, routerY, 110, 40, 'router', '10.0.0.1');
  const last = shown.activity.at(-1), positions = new Map([['router', routerY + 20]]);
  for (const [index, service] of services.entries()) {
    const y = first + index * step, middle = y + nodeHeight / 2;
    positions.set(service.id, middle);
    const hot = last && ((service.id === 'calls' && ['model_call', 'tool'].includes(last.fact.kind)) || service.id === `site:${last.fact.host}` || (service.id === 'dns' && last.fact.kind === 'resolved'));
    wire(`M140 ${routerY + 20} C153 ${routerY + 20},151 ${middle},164 ${middle}`, hot ? 'hot' : '', hot && newData);
    node(service.id, 164, y, width - 204, nodeHeight, service.title, service.address);
  }
  const visibleDestinations = destinations.slice(-2);
  const selectedDestination = selection?.startsWith('egress:') ? selection.slice(7) : upstream?.host;
  if (destinations.includes(selectedDestination) && !visibleDestinations.includes(selectedDestination)) visibleDestinations[0] = selectedDestination;
  const internetLabel = svg('text', { x: 26, y: internet + (destinations.length ? 23 : 38), class: 'map-label internet-label', role: 'button', tabindex: '0', 'aria-label': 'Internet' }, 'INTERNET ›');
  internetLabel.onclick = () => select('egress');
  internetLabel.onkeydown = (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select('egress'); } };
  map.append(internetLabel);
  for (const [index, host] of visibleDestinations.entries()) {
    const nodeWidth = (width - 52 - 12 * (visibleDestinations.length - 1)) / visibleDestinations.length;
    const x = 26 + index * (nodeWidth + 12);
    const purposes = [...new Set(shown.connections.filter((row) => row.host === host).map((row) => row.purpose))];
    for (const source of new Set(purposes.map((purpose) => purpose === 'setup' ? 'router' : ['model', 'page writer'].includes(purpose) ? 'calls' : 'signin'))) {
      const active = live && upstream?.host === host;
      wire(`M${source === 'router' ? 140 : width - 40} ${positions.get(source)} H${width - 25} V${internet + 58} H${x + nodeWidth}`, active ? 'outside observed hot' : 'outside observed', active);
    }
    node(`egress:${host}`, x, internet + 36, nodeWidth, 44, host, purposes.join(' · '), true);
  }
  if (!destinations.length) map.append(svg('text', { x: 150, y: internet + 38, class: 'map-empty' }, 'No connections'));
  const refusal = shown.activity.filter((row) => row.fact.kind === 'no_route').at(-1);
  if (refusal) {
    const y = bottom - 25;
    wire(`M85 ${routerY + 40} V${y - 18}`, 'no-route');
    map.append(svg('circle', { cx: 85, cy: y - 12, r: 7, class: 'refusal' }), svg('path', { d: `M82 ${y - 15} L88 ${y - 9} M88 ${y - 15} L82 ${y - 9}`, class: 'refusal-cross' }), svg('text', { x: 30, y: bottom - 8, class: 'map-refusal' }, refusal.fact.to));
  }
}
new ResizeObserver(() => graph(null, false)).observe($('map').parentElement);

const briefPath = (path) => path.split('?')[0];
function activityText(row) {
  const fact = row.fact;
  switch (fact.kind) {
    case 'resolved': return [fact.name, 'DNS', `${fact.name} → ${fact.address || 'no answer'}`, `site:${fact.name}`];
    case 'request': return [fact.host, 'HTTP', `${fact.method} ${briefPath(fact.path)} · ${fact.status}`, `site:${fact.host}`];
    case 'search': return [{google:'www.google.com',bing:'www.bing.com',duck_duck_go:'html.duckduckgo.com',you_tube:'www.youtube.com'}[fact.engine] || 'Search', 'Search', fact.query, 'sites'];
    case 'model_call': return [fact.host, 'HTTPS', `${fact.method} ${briefPath(fact.path)} · ${fact.status || 'connecting'}${fact.phase === 'streaming' ? ' · streaming' : ''}`, 'calls'];
    case 'tool': return ['model gateway', 'Tool', `${fact.tool === 'fetch' ? 'Fetch' : 'web_search'} · ${fact.target}`, 'calls'];
    case 'signin': return ['Sign-in', 'Policy', fact.open ? 'Opened sign-in' : ['Closed sign-in', fact.exceptions.join(', ')].filter(Boolean).join(' · '), 'signin'];
    case 'egress': return [fact.host, 'Upstream', `${fact.purpose} · ${fact.method} ${briefPath(fact.path)} · ${fact.status || fact.phase}`, `egress:${fact.host}`];
    case 'page_revision': {
      const target = fact.target.url || fact.target.host || fact.target.query || 'Pages';
      return [target, 'Writer', `${fact.action === 'rejected' ? 'Rejected' : 'Recovered'} · ${fact.reason}`, 'sites'];
    }
    case 'observation_failed': return ['Recording', 'Error', fact.reason, 'egress'];
    case 'no_route': return [fact.to, 'TCP', 'no route', 'router'];
    default: return ['', '', '', 'router'];
  }
}
function feed() {
  const atBottom = $('activity').scrollHeight - $('activity').scrollTop - $('activity').clientHeight < 24;
  $('activity').replaceChildren();
  for (const row of activityRows().filter((r) => r.fact.kind !== 'run_started' && !(r.fact.kind === 'egress' && r.fact.purpose === 'model')).slice(-100)) {
    const [target, protocol, text, selected] = activityText(row);
    const item = button('', () => select(selected), `activity-row ${row.fact.kind}`);
    item.append(element('span', stamp(row.at_ms), 'stamp'), element('span', target), element('span', protocol), element('span', text));
    item.title = `${target} · ${text}`;
    $('activity').append(item);
  }
  if (atBottom) $('activity').scrollTop = $('activity').scrollHeight;
  if (world?.preview) {
    $('preview-output').textContent = latest.activity.filter((r) => r.fact.kind !== 'run_started').slice(-10).map((r) => { const [host, protocol, text] = activityText(r); return `${protocol}  ${host}\n  ${text}`; }).join('\n\n');
  }
}
function activityRows() {
  const attempts = new Map();
  return shown.activity.filter((row) => {
    if (row.fact.kind !== 'no_route') return true;
    const key = `${row.fact.from}:${row.fact.to}`, previous = attempts.get(key);
    if (previous !== undefined && row.at_ms - previous <= 8000) return false;
    attempts.set(key, row.at_ms);
    return true;
  });
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
function requestFor(url) {
  try {
    const target = new URL(url); target.hash = '';
    return [...(shown.sites.find((site) => site.host === target.host)?.requests || [])].reverse().find((request) => request.url === target.href && request.method === 'GET');
  } catch { return null; }
}
function results(hits) {
  const list = element('div');
  if (!hits.length) list.append(element('p', 'No results', 'world-answer'));
  for (const hit of hits) {
    const opened = requestFor(hit.url);
    const row = button('', () => select(`page:${hit.url}`), `result ${opened ? 'opened' : 'unopened'}`);
    row.append(element('span', hit.title || hit.url, 'result-title'), element('small', hit.url), element('span', opened ? 'Opened' : 'Unopened', 'result-state'));
    list.append(row);
  }
  return list;
}
async function readPage(url, request, container) {
  const target = new URL(url);
  const query = new URLSearchParams({ scheme: target.protocol.slice(0, -1), host: target.host, path: `${target.pathname}${target.search}`, at_ms: request.at_ms });
  const response = await fetch(`/preview?${query}`);
  if (!response.ok) throw new Error(await response.text());
  const doc = new DOMParser().parseFromString(await response.text(), 'text/html');
  for (const node of doc.querySelectorAll('[hidden], [aria-hidden="true"]')) node.remove();
  for (const node of doc.querySelectorAll('[style]')) {
    if (node.style.display === 'none' || node.style.visibility === 'hidden') node.remove();
  }
  for (const node of doc.querySelectorAll('script,style,link,meta,iframe,object,embed,form,nav,header,footer,aside,svg,img,video,audio,source,template,noscript')) node.remove();
  let content = doc.querySelector('main, article, [role="main"]');
  if (!content) {
    content = doc.querySelector('h1')?.parentElement || doc.body;
    while (content !== doc.body && content.parentElement && content.querySelectorAll('p').length < 2) content = content.parentElement;
  }
  for (const node of [content, ...content.querySelectorAll('*')]) {
    for (const attribute of [...node.attributes]) node.removeAttribute(attribute.name);
  }
  const frame = element('iframe', undefined, 'recorded-page');
  frame.setAttribute('sandbox', ''); frame.referrerPolicy = 'no-referrer'; frame.title = url;
  frame.srcdoc = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><style>body{margin:24px;color:#243047;background:#fff;font:16px/1.7 system-ui}h1,h2,h3{line-height:1.25}a{color:#2c61bd}pre,table{white-space:pre-wrap;overflow-wrap:anywhere}*{max-width:100%;box-sizing:border-box}</style>${content.outerHTML}`;
  container.replaceChildren(frame);
}
let detailSignature = '';

function details() {
  if (!selection) { detailSignature = ''; return; }
  const signature = JSON.stringify([selection, selection.startsWith('page:') ? requestFor(selection.slice(5)) : shown]);
  if (signature === detailSignature) return;
  detailSignature = signature;
  const body = $('detail-body'), actions = $('detail-actions');
  const scroll = body.scrollTop;
  const expanded = new Set([...body.querySelectorAll('details[open]')].map((node) => node.dataset.key));
  body.replaceChildren(); actions.replaceChildren();
  const heading = (title, subtitle = '') => { $('detail-title').textContent = title; $('detail-subtitle').textContent = subtitle; };
  if (selection === 'calls') {
    heading('Model calls');
    if (!shown.calls.length) body.append(element('p', 'No calls', 'detail-empty'));
    for (const call of shown.calls) {
      const content = element('details'); content.dataset.key = String(call.call);
      content.open = expanded.has(content.dataset.key) || call.tools.length > 0 || !['complete', 'interrupted'].includes(call.phase);
      const summary = element('summary');
      summary.append(element('div', `${call.host} · ${call.method} ${call.path}`, 'label'), element('div', `${call.status || ''} ${call.phase}`, 'meta'));
      content.append(summary);
      for (const tool of call.tools) {
        content.append(element('p', tool.tool === 'fetch' ? 'Fetch' : 'Web search', 'meta'), element('p', tool.target, 'tool-query'));
        if (tool.error) content.append(element('p', tool.error, 'world-answer'));
        else if (tool.tool === 'web_search') content.append(results(tool.results));
        else content.append(element('p', 'World answer', 'world-answer'));
      }
      const row = element('div', undefined, 'detail-row'); row.append(element('span', stamp(call.at_ms), 'stamp'), content); body.append(row);
    }
  } else if (selection.startsWith('page:')) {
    const url = selection.slice(5), request = requestFor(url);
    const hit = shown.sites.flatMap((site) => site.searches.flatMap((search) => search.results)).concat(shown.calls.flatMap((call) => call.tools.flatMap((tool) => tool.results))).find((hit) => hit.url === url);
    heading(hit?.title || 'Page', url);
    body.append(element('p', request ? `Opened · ${request.status} · ${sourceName(request.source)}` : 'Unopened', 'page-state'));
    if (request?.has_preview) {
      const container = element('div', undefined, 'reading-view');
      body.append(container);
      let loaded = false;
      const read = button('Read page', async () => {
        if (loaded) {
          const expanded = document.body.classList.toggle('page-expanded');
          read.textContent = expanded ? 'Shrink page' : 'Expand page';
          return;
        }
        read.disabled = true;
        try {
          await readPage(url, request, container);
          loaded = true;
          read.textContent = 'Expand page';
        } catch (error) { notice(error.message); }
        finally { read.disabled = false; }
      });
      actions.append(read);
    }
    actions.append(button('Site', () => select(`site:${hostOf(url)}`)));
  } else if (selection.startsWith('site:')) {
    const name = selection.slice(5), site = shown.sites.find((site) => site.host === name);
    heading(name, site?.address || '');
    for (const search of site?.searches || []) {
      const content = element('div'); content.append(element('p', search.query, 'tool-query'), results(search.results));
      body.append(detailRow(search.at_ms, 'Search', `${search.results.length} results`, content));
    }
    for (const request of site?.requests || []) {
      const content = element('details'), summary = element('summary'), data = element('dl');
      content.dataset.key = `${request.method}:${request.path}:${request.at_ms}`;
      content.open = expanded.has(content.dataset.key);
      summary.append(element('div', `${request.method} ${request.path}`, 'label'), element('div', `${request.status} · ${size(request.bytes)} · ${sourceName(request.source)}`, 'meta'));
      for (const [key, value] of [...request.headers, ['content-type', request.content_type], ['elapsed', `${request.elapsed_ms} ms`]]) data.append(element('dt', key), element('dd', value));
      content.append(summary, data);
      if (request.has_preview) content.append(button('Page', () => select(`page:${request.url}`), 'more'));
      const row = element('div', undefined, 'detail-row'); row.append(element('span', stamp(request.at_ms), 'stamp'), content); body.append(row);
    }
    if (!site?.requests.length && !site?.searches.length) body.append(element('p', 'Unopened', 'detail-empty'));
  } else if (['egress', 'signin'].includes(selection) || selection.startsWith('egress:')) {
    const accepts = (row) => selection === 'signin' ? ['sign-in', 'token refresh', 'account', 'startup'].includes(row.purpose) : selection.startsWith('egress:') ? row.host === selection.slice(7) : true;
    const connections = shown.connections.filter(accepts), egress = shown.egress.filter((row) => accepts(row.fact) && row.fact.phase !== 'attempt');
    heading(selection === 'signin' ? 'Sign-in' : selection.startsWith('egress:') ? selection.slice(7) : 'Internet');
    if (shown.signin && ['signin', 'egress'].includes(selection)) {
      body.append(detailRow(shown.signin.at_ms, shown.signin.fact.open ? 'Sign-in open' : 'Sign-in closed', ''));
      const exceptions = element('details', undefined, 'exceptions');
      exceptions.append(element('summary', 'Exceptions'));
      for (const exception of shown.signin.fact.exceptions) exceptions.append(element('p', exception, 'meta'));
      body.append(exceptions);
    }
    for (const connection of connections.filter((connection) => !egress.some((row) => row.fact.host === connection.host && row.fact.purpose === connection.purpose))) body.append(detailRow(connection.at_ms, connection.host, connection.purpose));
    for (const row of egress) body.append(detailRow(row.at_ms, row.fact.host, `${row.fact.purpose} · ${row.fact.method} ${row.fact.path} · ${row.fact.status || row.fact.phase}`));
    if (!connections.length && !egress.length) body.append(element('p', 'No connections', 'detail-empty'));
  } else if (selection === 'sites') {
    heading('Sites');
    for (const site of localSites()) {
      const row = button(site.host, () => select(`site:${site.host}`), 'site-list'); row.append(element('small', site.address || '')); body.append(row);
    }
    if (!localSites().length) body.append(element('p', 'No sites', 'detail-empty'));
  } else if (selection === 'dns') {
    heading('DNS', '10.0.0.1:53');
    for (const row of shown.activity.filter((row) => row.fact.kind === 'resolved')) body.append(detailRow(row.at_ms, row.fact.name, row.fact.address || 'No answer'));
  } else if (selection === 'router') {
    heading('Router', '10.0.0.1');
    for (const row of activityRows().filter((row) => row.fact.kind === 'no_route')) body.append(detailRow(row.at_ms, row.fact.to, 'No route'));
  } else {
    heading('Workstation', hostStatus?.addresses.join(' · ') || '10.0.0.2');
    actions.append(button('Show agent', () => { select(null); $('agent').hidden = false; $('agent-toggle').setAttribute('aria-pressed', 'true'); }));
  }
  body.scrollTop = scroll;
}

function draw(upstream = null, newData = false) {
  graph(upstream, newData); feed(); details();
  $('clock').textContent = time(latest.at_ms);
  $('cursor-time').textContent = time(shown.at_ms);
  $('end-time').textContent = time(latest.at_ms);
  $('oldest').textContent = time(latest.oldest_ms);
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
  const forwarded = (row) => ['attempt', 'response', 'failed'].includes(row.fact.phase);
  const before = latest.egress.filter(forwarded).at(-1);
  const connected = !!latest.started_at_ms;
  latest = JSON.parse(event.data);
  const after = latest.egress.filter(forwarded).at(-1);
  const upstream = connected && JSON.stringify(before) !== JSON.stringify(after) ? after?.fact : null;
  if (live || shown.at_ms < latest.oldest_ms) { shown = latest; live = true; }
  draw(upstream, true);
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
    option.textContent = text;
  }
  if (world.preview) {
    $('console-status').hidden = true;
    $('terminal').hidden = true; $('screen').hidden = true;
    $('preview-console').hidden = false;
    $('terminal-tab').disabled = true; $('screen-tab').disabled = true;
    $('host-status').textContent = 'Preview';
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
$('story').onclick = async () => {
  $('story').disabled = true;
  try { const response = await fetch('/story', { method: 'POST' }); if (!response.ok) throw new Error(await response.text()); }
  catch (error) { notice(error.message); }
  finally { $('story').disabled = false; }
};
const scheme = matchMedia('(prefers-color-scheme: light)');
function terminalTheme() { return scheme.matches ? { background: '#ffffff', foreground: '#243047', cursor: '#275fbb' } : { background: '#0b0f18', foreground: '#d6dee8', cursor: '#9dbdf5' }; }
scheme.addEventListener('change', () => {
  const terminal = consoles.get('terminal');
  if (terminal) { terminal.component.dispose(); terminal.socket.close(); consoles.delete('terminal'); mountConsole(); }
});
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
  if (existing && existing.socket.readyState <= 1) return;
  existing?.component.dispose();
  mounting.add(kind);
  let socket;
  try {
    let create;
    if (kind === 'terminal') {
      const [library, component] = await Promise.all([import('/vendor/ghostty-web/dist/ghostty-web.js'), import('/terminal.mjs')]);
      const ghostty = await library.Ghostty.load('/vendor/ghostty-web/dist/ghostty-vt.wasm');
      create = (socket) => component.mount($('terminal'), library, socket, { ghostty, fontSize, fontFamily: 'monospace', theme: terminalTheme() });
    } else {
      const [{ default: RFB }, component] = await Promise.all([import('/vendor/novnc/core/rfb.js'), import('/screen.mjs')]);
      create = (socket) => component.mount($('screen'), RFB, socket);
    }
    socket = new WebSocket(socketUrl(kind));
    socket.addEventListener('close', () => { if (activeConsole === kind && consoles.get(kind)?.socket === socket) { $('console-status').hidden = false; $('console-status').textContent = 'Console disconnected. Select Terminal or Screen to reconnect.'; } });
    socket.addEventListener('error', () => notice('Could not connect to the workstation console'));
    $(kind).replaceChildren();
    const component = create(socket);
    consoles.set(kind, { component, socket });
  } catch (error) { socket?.close(); notice(`Console unavailable: ${error.message}`); }
  finally { mounting.delete(kind); }
}
for (const [id, change] of [['smaller-text', -1], ['larger-text', 1]]) {
  $(id).onclick = () => {
    fontSize = Math.max(16, Math.min(26, fontSize + change));
    consoles.get('terminal')?.component.setFontSize(fontSize);
  };
}
$('terminal-tab').onclick = () => { activeConsole = 'terminal'; mountConsole(); };
$('screen-tab').onclick = () => { activeConsole = 'screen'; mountConsole(); };
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
