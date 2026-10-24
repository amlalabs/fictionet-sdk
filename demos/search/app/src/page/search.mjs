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
const stamp = (ms) => new Date((shown.started_at_ms || Date.now()) + ms).toLocaleTimeString([], { hour12: false, timeZone: 'UTC' });
const time = stamp;
const size = (bytes) => bytes < 1000 ? `${bytes} B` : `${Math.round(bytes / 1000)} KB`;
const quantity = (n, word, plural = `${word}s`) => `${n} ${n === 1 ? word : plural}`;
const sourceName = (source) => source.kind === 'copy' ? source.captured ? `Copied · ${source.captured.slice(0, 10)}` : 'Copied' : source.kind === 'live' ? 'live' : 'model-written';
const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };
let shown = { at_ms: 0, sites: [], calls: [], activity: [], connections: [], egress: [], signin: null };
let selection = null, world = null;
let noticeTimer, activeConsole = 'terminal', hostStatus = null;
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
  if (key !== selection) document.body.classList.toggle('page-expanded', !!key?.startsWith('page:') && !!requestFor(key.slice(5))?.has_preview);
  document.body.classList.toggle('page-selected', !!key?.startsWith('page:'));
  selection = key;
  $('details').hidden = !key;
  document.body.classList.toggle('details-open', !!key);
  if (key) { $('agent').hidden = false; $('agent-toggle').setAttribute('aria-pressed', 'true'); }
  draw();
}
$('close-details').onclick = () => select(null);
$('agent-toggle').onclick = () => {
  $('agent').hidden = !$('agent').hidden;
  $('agent-toggle').setAttribute('aria-pressed', String(!$('agent').hidden));
  $('agent-toggle').textContent = $('agent').hidden ? 'Show agent' : 'Hide agent';
};
function localSites() {
  const upstream = new Set([...shown.connections.filter((row) => ['model', 'account', 'page writer'].includes(row.purpose)).map((row) => row.host), ...shown.calls.map((call) => call.host)]);
  return shown.sites.filter((site) => !upstream.has(site.host));
}
const purposeName = (purpose) => ({ model: 'Model', 'page writer': 'Page writer', account: 'Sign-in', live_search: 'Search', live_capture: 'Page copy' })[purpose];
const phaseName = (phase) => ({ connecting: 'Connecting', receiving: 'Receiving', streaming: 'Streaming', complete: 'Complete', interrupted: 'Interrupted', attempt: 'Connecting', response: 'Received', failed: 'Failed' })[phase];

function graph() {
  const map = $('map');
  map.replaceChildren();
  const heading = element('div', undefined, 'map-heading');
  for (const [label, key] of [['VM', 'workstation'], ['World', 'sites'], ['Internet', 'egress']]) heading.append(button(label, () => select(key)));
  map.append(heading);
  const sites = localSites();
  const facts = shown.activity.map((row) => row.fact);
  const searches = shown.sites.flatMap((site) => site.searches).length + shown.calls.flatMap((call) => call.tools.filter((tool) => tool.tool === 'web_search')).length;
  const modelHosts = (purpose) => [...new Set(shown.connections.filter((row) => row.purpose === purpose).map((row) => row.host))];
  const services = [
    { id: 'dns', title: 'DNS', subtitle: '10.0.0.1:53', reached: facts.some((fact) => fact.kind === 'resolved') },
    { id: 'search', title: 'Search', subtitle: searches ? quantity(searches, 'search', 'searches') : '', reached: searches > 0, purpose: 'live_search' },
    { id: 'sites', title: 'Sites', subtitle: sites.length ? quantity(sites.length, 'site') : '', reached: sites.some((site) => site.requests.length), purpose: 'live_capture' },
    { id: 'calls', title: 'Model gateway', subtitle: shown.calls.length ? quantity(shown.calls.length, 'call') : '', reached: shown.calls.length > 0, purpose: 'model' },
    { id: 'writer', title: 'Page writer', subtitle: '', reached: false, purpose: 'page writer' },
    { id: 'signin', title: 'Sign-in', subtitle: shown.signin?.fact.open ? 'Open' : 'Closed', reached: modelHosts('account').length > 0, purpose: 'account' },
    { id: 'router', title: 'Router', subtitle: facts.filter((fact) => fact.kind === 'no_route').at(-1)?.to || '10.0.0.1', reached: facts.some((fact) => fact.kind === 'no_route') },
  ];
  const lanes = element('div', undefined, 'traffic-lanes');
  const boundary = element('div', undefined, 'world-boundary');
  lanes.append(boundary);
  const vm = button('', () => select('workstation'), 'vm-node');
  vm.append(element('span', '>_', 'vm-icon'), element('strong', 'workstation'), element('small', hostStatus?.addresses[0] || '10.0.0.2'));
  lanes.append(vm);
  for (const [index, service] of services.entries()) {
    const lane = element('div', undefined, 'traffic-lane');
    const hosts = modelHosts(service.purpose);
    const control = button('', () => select(service.id), `service ${service.reached || hosts.length ? 'active' : 'unused'}`);
    control.dataset.service = service.id;
    control.dataset.reached = service.reached;
    if (service.id === 'router' && service.reached) control.classList.add('refused');
    control.setAttribute('aria-pressed', String(selection === service.id));
    const label = element('span', undefined, 'service-label');
    label.append(element('strong', service.title));
    if (service.subtitle) label.append(element('small', service.subtitle, service.id === 'router' && service.reached ? 'map-refusal' : ''));
    control.append(label);
    lane.append(control);
    if (hosts.length) {
      control.classList.add('has-egress');
      const destinations = element('div', undefined, 'destinations');
      if (service.purpose === 'live_capture') {
        const pages = shown.sites.flatMap((site) => site.requests.filter((request) => request.source.kind === 'live' && request.has_preview));
        const copies = button('', () => select('copies'), 'destination');
        copies.append(element('strong', 'Page copies'), element('small', `${quantity(pages.length, 'page')} · ${quantity(hosts.length, 'host')}`));
        destinations.append(copies);
      } else {
        for (const host of hosts) {
          const destination = button('', () => select(`egress:${host}`), 'destination');
          destination.append(element('strong', host), element('small', purposeName(service.purpose)));
          destinations.append(destination);
        }
      }
      lane.append(destinations);
    } else if (!index && !shown.connections.length) lane.append(element('p', 'No connections', 'map-empty'));
    lanes.append(lane);
  }
  map.append(lanes);
  drawWires();
}

function drawWires() {
  const lanes = $('map').querySelector('.traffic-lanes');
  if (!lanes || !lanes.clientWidth) return;
  lanes.querySelector('svg')?.remove();
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.classList.add('traffic-wires');
  svg.setAttribute('width', lanes.clientWidth);
  svg.setAttribute('height', lanes.clientHeight);
  svg.setAttribute('aria-hidden', 'true');
  const origin = lanes.getBoundingClientRect();
  const point = (node, side) => {
    const rect = node.getBoundingClientRect();
    return { x: rect[side] - origin.left, y: rect.top - origin.top + rect.height / 2 };
  };
  const line = (d, refused = false) => {
    const path = document.createElementNS(svg.namespaceURI, 'path');
    path.setAttribute('d', d);
    if (refused) path.classList.add('refused');
    svg.append(path);
  };
  const port = ({ x, y }, refused = false) => {
    const dot = document.createElementNS(svg.namespaceURI, 'circle');
    dot.setAttribute('cx', x); dot.setAttribute('cy', y); dot.setAttribute('r', 2.5);
    if (refused) dot.classList.add('refused');
    svg.append(dot);
  };
  const vm = point(lanes.querySelector('.vm-node'), 'right');
  const reached = [...lanes.querySelectorAll('.service[data-reached="true"]')];
  if (reached.length) {
    const points = reached.map((node) => point(node, 'left'));
    const junction = (vm.x + points[0].x) / 2;
    line(`M${vm.x},${vm.y} H${junction}`);
    line(`M${junction},${Math.min(vm.y, ...points.map((p) => p.y))} V${Math.max(vm.y, ...points.map((p) => p.y))}`);
    for (const [index, node] of reached.entries()) {
      const p = points[index], refused = node.classList.contains('refused');
      line(`M${junction},${p.y} H${p.x}`, refused);
      port(p, refused);
    }
  }
  for (const lane of lanes.querySelectorAll('.traffic-lane')) {
    const service = lane.querySelector('.service');
    const destinations = [...lane.querySelectorAll('.destination')];
    if (!destinations.length) continue;
    const start = point(service, 'right');
    const ends = destinations.map((node) => point(node, 'left'));
    const junction = (start.x + ends[0].x) / 2;
    line(`M${start.x},${start.y} H${junction}`);
    line(`M${junction},${Math.min(start.y, ...ends.map((p) => p.y))} V${Math.max(start.y, ...ends.map((p) => p.y))}`);
    port(start);
    for (const end of ends) {
      line(`M${junction},${end.y} H${end.x - 4} m-4,-3 l4,3 l-4,3`);
    }
  }
  lanes.prepend(svg);
}
new ResizeObserver(drawWires).observe($('map'));

const briefPath = (path) => path.split('?')[0];
const isAsset = (request) => /^(image\/|font\/|audio\/|video\/|text\/css|(?:text|application)\/(?:x-)?javascript|application\/(?:font|x-font|vnd\.ms-fontobject))/.test(request.content_type)
  || /\.(?:css|[cm]?js|map|ico|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|otf|eot|mp[34]|webm)(?:\?|$)/i.test(request.path);
function pageAssets() {
  const groups = new Map();
  let page = null;
  const byHost = new Map();
  for (const row of shown.activity) {
    const fact = row.fact;
    if (fact.kind !== 'request') continue;
    if (isAsset(fact)) {
      const parent = byHost.get(fact.host) || page;
      if (parent) groups.get(parent).push(row);
    } else {
      page = row;
      byHost.set(fact.host, row);
      groups.set(row, []);
    }
  }
  return groups;
}
function activityText(row) {
  const fact = row.fact;
  switch (fact.kind) {
    case 'resolved': return [fact.name, 'DNS', `${fact.name} → ${fact.address || 'no answer'}`, `site:${fact.name}`];
    case 'request': return [`Opened ${fact.host}${briefPath(fact.path) === '/' ? '' : briefPath(fact.path)}`, 'Page', `${fact.status} · ${sourceName(fact.source)}`, fact.preview || /(?:text\/html|application\/pdf)/.test(fact.content_type) ? `page:${fact.scheme}://${fact.host}${fact.path}` : `site:${fact.host}`];
    case 'search': return [`Searched “${fact.query}”`, 'Search', quantity(fact.results.length, 'result'), 'search'];
    case 'model_call': return ['Asked the model', 'HTTPS', `${fact.host} · ${phaseName(fact.phase)}`, 'calls'];
    case 'tool': return [`${fact.tool === 'fetch' ? 'Fetched' : 'Searched'} ${fact.target}`, 'Tool', fact.error || (fact.tool === 'fetch' ? 'World answer' : quantity(fact.results.length, 'result')), 'calls'];
    case 'signin': return ['Sign-in', 'Policy', fact.open ? 'Open' : 'Closed', 'signin'];
    case 'egress': {
      if (fact.purpose === 'live_capture') {
        const copies = activityRows().filter((row) => row.fact.kind === 'egress' && row.fact.purpose === 'live_capture');
        return ['Page copies', 'Upstream', `${quantity(copies.length, 'request')} · ${quantity(new Set(copies.map((row) => row.fact.host)).size, 'host')}`, 'copies'];
      }
      return [fact.host, 'Upstream', `${purposeName(fact.purpose)} · ${fact.method} ${briefPath(fact.path)} · ${fact.status || phaseName(fact.phase)}`, `egress:${fact.host}`];
    }
    case 'page_revision': {
      const target = fact.target.url ? new URL(fact.target.url).hostname : fact.target.host || 'Search';
      return [target, 'Writer', 'Revising page', 'writer'];
    }
    case 'no_route': return [`Tried ${fact.to}`, 'TCP', 'No route', 'router'];
    default: return ['', '', '', 'router'];
  }
}
function feed() {
  const scrollTop = $('activity').scrollTop;
  const expanded = new Set([...$('activity').querySelectorAll('details[open]')].map((node) => node.dataset.key));
  $('activity').replaceChildren();
  const assets = pageAssets();
  const rows = activityRows().filter((row) => ['request', 'search', 'model_call', 'tool', 'no_route'].includes(row.fact.kind) && !(row.fact.kind === 'request' && isAsset(row.fact)));
  for (const row of rows.reverse()) {
    const [target, , text, selected] = activityText(row);
    const item = button('', () => select(selected), `activity-row ${row.fact.kind}`);
    item.append(element('span', stamp(row.at_ms), 'stamp'), element('span', target), element('span', text));
    item.title = `${target} · ${text}${row.fact.kind === 'page_revision' ? ` · ${row.fact.reason}` : ''}`;
    $('activity').append(item);
    const resources = assets.get(row);
    if (resources?.length) {
      const group = element('details', undefined, 'page-assets');
      group.dataset.key = `${row.at_ms}:${row.fact.host}:${row.fact.path}`;
      group.open = expanded.has(group.dataset.key);
      group.append(element('summary', quantity(resources.length, 'asset')));
      for (const resource of resources) {
        const fact = resource.fact;
        group.append(button(`${fact.host}${fact.path} · ${fact.status}`, () => select(`site:${fact.host}`), 'asset-row'));
      }
      $('activity').append(group);
    }
  }
  if (!rows.length) $('activity').append(element('p', 'Waiting for activity', 'feed-empty'));
  $('activity').scrollTop = scrollTop;

}
function activityRows() {
  const upstream = new Map();
  for (const row of shown.activity) if (row.fact.kind === 'egress') upstream.set(row.fact.attempt, row);
  const attempts = new Map();
  return shown.activity.filter((row) => {
    if (row.fact.kind === 'egress') return upstream.get(row.fact.attempt) === row;
    if (row.fact.kind !== 'no_route') return true;
    const key = `${row.fact.from}:${row.fact.to}`, previous = attempts.get(key);
    attempts.set(key, row.at_ms);
    if (previous !== undefined && row.at_ms - previous <= 30000) return false;
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
  const query = new URLSearchParams({ scheme: target.protocol.slice(0, -1), host: target.host, path: `${target.pathname}${target.search}` });
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
      summary.append(element('div', `${call.host} · ${call.method} ${call.path}`, 'label'), element('div', phaseName(call.phase), 'meta'));
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
      const container = element('div', 'Loading page…', 'reading-view');
      body.append(container);
      readPage(url, request, container).catch((error) => { container.textContent = error.message; });
      const read = button(document.body.classList.contains('page-expanded') ? 'Shrink page' : 'Expand page', () => {
        const expanded = document.body.classList.toggle('page-expanded');
        read.textContent = expanded ? 'Shrink page' : 'Expand page';
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
      summary.append(element('div', `${request.method} ${request.path}`, 'label'), element('div', `${request.status} · ${size(request.bytes)} on the wire · ${sourceName(request.source)}`, 'meta'));
      for (const [key, value] of [...request.headers, ['content-type', request.content_type], ['elapsed', request.elapsed_ms ? `${request.elapsed_ms} ms` : '<1 ms']]) data.append(element('dt', key), element('dd', value));
      content.append(summary, data);
      if (request.has_preview) content.append(button('Page', () => select(`page:${request.url}`), 'more'));
      const row = element('div', undefined, 'detail-row'); row.append(element('span', stamp(request.at_ms), 'stamp'), content); body.append(row);
    }
    if (!site?.requests.length && !site?.searches.length) body.append(element('p', 'Unopened', 'detail-empty'));
  } else if (selection === 'copies') {
    heading('Page copies');
    for (const site of shown.sites) for (const request of site.requests.filter((request) => request.source.kind === 'live' && request.has_preview)) {
      const row = button(request.url, () => select(`page:${request.url}`), 'site-list');
      body.append(row);
    }
    const resources = element('details', undefined, 'exceptions');
    resources.append(element('summary', 'Connections'));
    for (const row of activityRows().filter((row) => row.fact.kind === 'egress' && row.fact.purpose === 'live_capture')) resources.append(detailRow(row.at_ms, row.fact.host, `${row.fact.method} ${row.fact.path} · ${row.fact.status || phaseName(row.fact.phase)}`));
    body.append(resources);
  } else if (['egress', 'signin'].includes(selection) || selection.startsWith('egress:')) {
    const accepts = (row) => selection === 'signin' ? row.purpose === 'account' : selection.startsWith('egress:') ? row.host === selection.slice(7) : true;
    const connections = shown.connections.filter(accepts), egress = shown.egress.filter((row) => accepts(row.fact) && row.fact.phase !== 'attempt');
    heading(selection === 'signin' ? 'Sign-in' : selection.startsWith('egress:') ? selection.slice(7) : 'Internet');
    if (shown.signin && ['signin', 'egress'].includes(selection)) {
      body.append(detailRow(shown.signin.at_ms, shown.signin.fact.open ? 'Sign-in open' : 'Sign-in closed', ''));
      if (shown.signin.fact.exceptions.length) {
        const exceptions = element('details', undefined, 'exceptions');
        exceptions.open = true;
        exceptions.append(element('summary', 'Exceptions'));
        for (const exception of shown.signin.fact.exceptions) exceptions.append(element('p', exception, 'meta'));
        body.append(exceptions);
      }
    }
    for (const connection of connections.filter((connection) => !egress.some((row) => row.fact.host === connection.host && row.fact.purpose === connection.purpose))) body.append(detailRow(connection.at_ms, connection.host, purposeName(connection.purpose)));
    for (const row of egress) body.append(detailRow(row.at_ms, row.fact.host, `${purposeName(row.fact.purpose)} · ${row.fact.method} ${row.fact.path} · ${row.fact.status || phaseName(row.fact.phase)}`));
    if (!connections.length && !egress.length) body.append(element('p', 'No connections', 'detail-empty'));
  } else if (selection === 'search') {
    heading('Search');
    const searches = [...shown.sites.flatMap((site) => site.searches), ...shown.calls.flatMap((call) => call.tools.filter((tool) => tool.tool === 'web_search').map((tool) => ({ ...tool, query: tool.target })))].sort((a, b) => b.at_ms - a.at_ms);
    for (const search of searches) {
      const content = element('div'); content.append(element('p', search.query, 'tool-query'), search.error ? element('p', search.error, 'world-answer') : results(search.results));
      body.append(detailRow(search.at_ms, 'Search', `${search.results.length} results`, content));
    }
    if (!searches.length) body.append(element('p', 'No searches', 'detail-empty'));
  } else if (selection === 'writer') {
    heading('Page writer');
    for (const row of activityRows().filter((row) => row.fact.kind === 'egress' && row.fact.purpose === 'page writer')) body.append(detailRow(row.at_ms, row.fact.host, `${row.fact.method} ${row.fact.path} · ${row.fact.status || phaseName(row.fact.phase)}`));
    for (const row of shown.activity.filter((row) => row.fact.kind === 'page_revision')) {
      const fact = row.fact;
      const target = fact.target.url || fact.target.host || fact.target.query || 'Cast';
      body.append(detailRow(row.at_ms, target, 'Revising page', element('p', fact.reason, 'writer-error')));
    }
    if (!body.childElementCount) body.append(element('p', 'No pages written', 'detail-empty'));
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

function draw() {
  graph(); feed(); details();
  $("clock").textContent = time(shown.at_ms);
}
const stream = new EventSource("/state");
stream.onerror = () => { $("clock").title = "Reconnecting"; };
stream.onopen = () => { $("clock").title = ""; };
stream.onmessage = (event) => {
  shown = JSON.parse(event.data);
  draw();
};
async function loadWorld() {
  const response = await fetch('/world');
  if (!response.ok) throw new Error('Could not read the world settings');
  world = await response.json();
  $('world-date').textContent = world.date;
  $('brief').textContent = world.instructions;
  const active = world.source.kind === 'copy' ? 'copied' : world.source.kind === 'live' ? 'live' : 'model_written';
  for (const control of $('source').querySelectorAll('button')) {
    const availability = world[control.dataset.source];
    control.disabled = availability.kind !== 'available';
    control.setAttribute('aria-pressed', String(control.dataset.source === active));
    control.title = { no_captures: 'No captures', no_page_writer: 'No page writer', no_search_key: 'No search key' }[availability.reason] || '';
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
for (const control of $('source').querySelectorAll('button')) {
  control.onclick = async () => {
    if (control.getAttribute('aria-pressed') === 'true') return;
    for (const control of $('source').querySelectorAll('button')) control.disabled = true;
    try { await command({ command: 'set_source', source: control.dataset.source }); }
    catch (error) { notice(error.message); await loadWorld(); }
  };
}
$('restart').onclick = async () => { $('restart').disabled = true; try { await command({ command: 'restart' }); select(null); } catch (error) { $('world-error').textContent = error.message; } finally { $('restart').disabled = false; } };
async function mountConsole() {
  if (!hostStatus) return;
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
      await document.fonts.load('19px "JetBrains Mono"');
      const ghostty = await library.Ghostty.load('/vendor/ghostty-web/dist/ghostty-vt.wasm');
      create = (socket) => component.mount($('terminal'), library, socket, { ghostty, fontSize: 19, fontFamily: 'JetBrains Mono', theme: { background: '#151917', foreground: '#dce2dc', cursor: '#dce2dc' } });
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
$('terminal-tab').onclick = () => { activeConsole = 'terminal'; mountConsole(); };
$('screen-tab').onclick = () => { activeConsole = 'screen'; mountConsole(); };
const status = new EventSource('/host/state');
status.onmessage = (event) => {
  const next = JSON.parse(event.data);
  const changed = JSON.stringify(next) !== JSON.stringify(hostStatus);
  hostStatus = next;
  if (changed) mountConsole();
};
loadWorld().then(() => mountConsole()).catch((error) => notice(error.message));
draw();
window.addEventListener('pagehide', () => { stream.close(); status.close(); for (const console of consoles.values()) { console.component.dispose(); console.socket.close(); } });
