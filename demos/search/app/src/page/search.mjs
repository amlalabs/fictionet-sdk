const $ = (id) => document.getElementById(id);
const SVG = 'http://www.w3.org/2000/svg';
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
const svgNode = (tag, attributes = {}) => {
  const node = document.createElementNS(SVG, tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  return node;
};
const stamp = (ms) => new Date((shown.started_at_ms || Date.now()) + ms).toLocaleTimeString([], { hour12: false, timeZone: 'UTC' });
const size = (bytes) => bytes < 1000 ? `${bytes} B` : `${Math.round(bytes / 1000)} KB`;
const quantity = (n, word, plural = `${word}s`) => `${n} ${n === 1 ? word : plural}`;
const sourceName = (source) => source.kind === 'copy' ? source.captured ? `Copied ${source.captured.slice(0, 10)}` : 'Copied' : source.kind === 'live' ? 'Live' : 'Model-written';
const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };
const originOf = (url) => { try { return new URL(url).origin; } catch { return null; } };
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
let shown = { at_ms: 0, sites: [], calls: [], activity: [], connections: [], egress: [], signin: null };
let selection = null, world = null;
let noticeTimer, activeConsole = 'terminal', hostStatus = null;
const consoles = new Map();
const mounting = new Set();
const socketUrl = (path) => `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/${path}`;
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
  if (key) { $('agent').hidden = false; $('agent-toggle').setAttribute('aria-pressed', 'true'); $('agent-toggle').textContent = 'Hide agent'; }
  draw();
}
$('close-details').onclick = () => select(null);
$('agent-toggle').onclick = () => {
  $('agent').hidden = !$('agent').hidden;
  $('agent-toggle').setAttribute('aria-pressed', String(!$('agent').hidden));
  $('agent-toggle').textContent = $('agent').hidden ? 'Show agent' : 'Hide agent';
};
const UPSTREAM = ['model', 'account', 'page writer', 'original'];
function localSites() {
  const upstream = new Set([...shown.connections.filter((row) => UPSTREAM.includes(row.purpose)).map((row) => row.host), ...shown.calls.map((call) => call.host)]);
  return shown.sites.filter((site) => !upstream.has(site.host));
}
const purposeName = (purpose) => ({ model: 'Model', 'page writer': 'Page writer', account: 'Sign-in', live_search: 'Search', live_capture: 'Page copy', original: 'Original' })[purpose];
const phaseName = (phase) => ({ connecting: 'Connecting', receiving: 'Receiving', streaming: 'Streaming', complete: 'Complete', interrupted: 'Interrupted', attempt: 'Connecting', response: 'Received', failed: 'Failed' })[phase];

// The network map is built once; each state only changes its text, its
// destinations and, when the layout moves, its wires.
const SERVICES = [
  { id: 'dns', title: 'DNS' },
  { id: 'search', title: 'Search', purposes: ['live_search'] },
  { id: 'sites', title: 'Sites', purposes: ['live_capture'] },
  { id: 'calls', title: 'Model gateway', purposes: ['model'] },
  { id: 'writer', title: 'Page writer', purposes: ['page writer', 'original'] },
  { id: 'signin', title: 'Sign-in', purposes: ['account'] },
  { id: 'router', title: 'Router' },
];
const map = { lanes: null, wires: null, pulses: null, vm: null, services: new Map(), signature: '' };
function buildMap() {
  const root = $('map');
  const lanes = element('div', undefined, 'traffic-lanes');
  const world = button('', () => select('sites'), 'world-boundary');
  world.append(element('span', 'World', 'region-label'));
  const internet = button('', () => select('egress'), 'internet-boundary');
  internet.append(element('span', 'Internet', 'region-label'));
  map.wires = svgNode('svg', { class: 'traffic-wires', 'aria-hidden': 'true' });
  map.pulses = svgNode('svg', { class: 'traffic-pulses', 'aria-hidden': 'true' });
  map.vm = button('', () => select('workstation'), 'vm-node');
  map.vm.append(element('strong', 'Workstation'), element('small', '10.0.0.2'));
  lanes.append(world, internet, map.wires, map.vm);
  for (const service of SERVICES) {
    const lane = element('div', undefined, 'traffic-lane');
    const control = button('', () => select(service.id), 'service unused');
    control.dataset.service = service.id;
    const title = element('strong', service.title), detail = element('small', '');
    control.append(title, detail);
    const destinations = element('div', undefined, 'destinations');
    lane.append(control, destinations);
    lanes.append(lane);
    map.services.set(service.id, { ...service, control, detail, destinations, signature: '' });
  }
  lanes.append(map.pulses);
  root.replaceChildren(lanes);
  map.lanes = lanes;
}
function graph() {
  if (!map.lanes) buildMap();
  map.vm.querySelector('small').textContent = hostStatus?.addresses[0] || '10.0.0.2';
  map.vm.setAttribute('aria-pressed', String(selection === 'workstation'));
  const sites = localSites();
  const facts = shown.activity.map((row) => row.fact);
  const searches = shown.sites.flatMap((site) => site.searches).length + shown.calls.flatMap((call) => call.tools.filter((tool) => tool.tool === 'web_search')).length;
  const refusedTo = facts.filter((fact) => fact.kind === 'no_route').at(-1)?.to;
  const state = {
    dns: { detail: '10.0.0.1', reached: facts.some((fact) => fact.kind === 'resolved') },
    search: { detail: searches ? quantity(searches, 'search', 'searches') : '', reached: searches > 0 },
    sites: { detail: sites.length ? quantity(sites.length, 'site') : '', reached: sites.some((site) => site.requests.length) },
    calls: { detail: shown.calls.length ? quantity(shown.calls.length, 'call') : '', reached: shown.calls.length > 0 },
    writer: { detail: '', reached: false },
    signin: { detail: shown.signin?.fact.open ? 'Open' : 'Closed', reached: false },
    router: { detail: refusedTo ? `No route to ${refusedTo}` : '', reached: !!refusedTo, refused: !!refusedTo },
  };
  for (const service of map.services.values()) {
    const { detail, reached, refused } = state[service.id];
    const purposes = service.purposes || [];
    const connections = shown.connections.filter((row) => purposes.includes(row.purpose));
    const used = reached || connections.length > 0;
    service.control.className = `service ${used ? 'used' : 'unused'}${refused ? ' refused' : ''}`;
    service.control.dataset.reached = String(reached);
    service.control.setAttribute('aria-pressed', String(selection === service.id));
    if (service.detail.textContent !== detail) service.detail.textContent = detail;
    const destinations = destinationsOf(service, connections);
    const signature = JSON.stringify(destinations.map(({ key, title, meta }) => [key, title, meta, selection]));
    if (signature !== service.signature) {
      service.signature = signature;
      service.destinations.replaceChildren(...destinations.map(({ key, title, meta, target, host }) => {
        const node = button('', () => select(target), host ? 'destination host' : 'destination');
        node.dataset.edge = key;
        node.setAttribute('aria-pressed', String(selection === target));
        node.append(element('strong', title));
        if (meta) node.append(element('small', meta));
        return node;
      }));
    }
  }
  const layout = JSON.stringify([...map.services.values()].map((service) => [service.control.dataset.reached, service.signature.length, service.destinations.childElementCount]).concat([map.lanes.clientWidth, map.lanes.clientHeight]));
  if (layout !== map.signature) drawWires();
}
function destinationsOf(service, connections) {
  const rows = [];
  for (const purpose of service.purposes || []) {
    const hosts = [...new Set(connections.filter((row) => row.purpose === purpose).map((row) => row.host))];
    if (!hosts.length) continue;
    if (purpose === 'live_capture' || purpose === 'original') {
      const requests = shown.egress.filter((row) => row.fact.purpose === purpose && row.fact.phase !== 'attempt');
      const target = purpose === 'original' ? 'originals' : 'copies';
      rows.push({ key: `${service.id}>${target}`, target, host: false, title: purpose === 'original' ? 'Originals' : 'Page copies', meta: `${quantity(requests.length, 'request')} · ${quantity(hosts.length, 'host')}` });
    } else {
      for (const host of hosts) rows.push({ key: `${service.id}>${host}`, target: `egress:${host}`, host: true, title: host, meta: '' });
    }
  }
  return rows;
}
// Every wire is one path from its start to its end, so a pulse can travel it.
function drawWires() {
  const lanes = map.lanes;
  if (!lanes?.clientWidth) return;
  map.signature = JSON.stringify([...map.services.values()].map((service) => [service.control.dataset.reached, service.signature.length, service.destinations.childElementCount]).concat([lanes.clientWidth, lanes.clientHeight]));
  for (const svg of [map.wires, map.pulses]) { svg.setAttribute('width', lanes.clientWidth); svg.setAttribute('height', lanes.clientHeight); }
  map.wires.replaceChildren();
  const origin = lanes.getBoundingClientRect();
  const point = (node, side) => {
    const rect = node.getBoundingClientRect();
    return { x: rect[side] - origin.left, y: rect.top - origin.top + rect.height / 2 };
  };
  const route = (from, to, mid) => {
    if (Math.abs(from.y - to.y) < 1) return `M${from.x},${from.y} H${to.x}`;
    const r = Math.min(6, Math.abs(to.y - from.y) / 2), down = to.y > from.y ? 1 : -1;
    return `M${from.x},${from.y} H${mid - r} Q${mid},${from.y} ${mid},${from.y + down * r} V${to.y - down * r} Q${mid},${to.y} ${mid + r},${to.y} H${to.x}`;
  };
  const wire = (key, d, refused) => map.wires.append(svgNode('path', { d, 'data-edge': key, class: refused ? 'refused' : '' }));
  const vm = point(map.vm, 'right');
  for (const service of map.services.values()) {
    if (service.control.dataset.reached !== 'true') continue;
    const end = point(service.control, 'left');
    const refused = service.control.classList.contains('refused');
    wire(`vm>${service.id}`, route(vm, end, vm.x + (end.x - vm.x) / 2), refused);
    map.wires.append(svgNode('circle', { cx: end.x, cy: end.y, r: 2.5, class: refused ? 'refused' : '' }));
  }
  for (const service of map.services.values()) {
    const destinations = [...service.destinations.children];
    if (!destinations.length) continue;
    const start = point(service.control, 'right');
    for (const node of destinations) {
      const end = point(node, 'left');
      wire(node.dataset.edge, route(start, { x: end.x - 6, y: end.y }, start.x + (end.x - start.x) / 2));
    }
    map.wires.append(svgNode('circle', { cx: start.x, cy: start.y, r: 2.5 }));
  }
}
new ResizeObserver(() => { map.signature = ''; drawWires(); }).observe($('map'));

// A pulse runs along the wires a request actually took.
const running = new Map();
function pulse(...edges) {
  const legs = edges.map((edge) => map.wires?.querySelector(`path[data-edge="${CSS.escape(edge)}"]`)).filter(Boolean);
  if (!legs.length) return;
  const key = edges.join(' ');
  if (performance.now() - (running.get(key) || 0) < 240) return;
  running.set(key, performance.now());
  const refused = legs.some((leg) => leg.classList.contains('refused'));
  if (reducedMotion.matches) {
    for (const leg of legs) { leg.classList.add('lit'); setTimeout(() => leg.classList.remove('lit'), 700); }
    return;
  }
  const dot = svgNode('circle', { r: 3, class: refused ? 'refused' : '' });
  map.pulses.append(dot);
  const total = legs.reduce((sum, leg) => sum + leg.getTotalLength(), 0);
  const duration = 260 + total * 1.6;
  const start = performance.now();
  const frame = (now) => {
    const t = Math.min(1, (now - start) / duration);
    let along = (1 - (1 - t) ** 2) * total;
    let leg = legs[0];
    for (const candidate of legs) { leg = candidate; const length = candidate.getTotalLength(); if (along <= length) break; along -= length; }
    if (!leg.isConnected) { dot.remove(); return; }
    const at = leg.getPointAtLength(Math.min(along, leg.getTotalLength()));
    dot.setAttribute('cx', at.x); dot.setAttribute('cy', at.y);
    dot.style.opacity = t > 0.85 ? String((1 - t) / 0.15) : '1';
    if (t < 1) requestAnimationFrame(frame); else dot.remove();
  };
  requestAnimationFrame(frame);
}
const SEARCH_HOSTS = new Set(['www.google.com', 'www.bing.com', 'html.duckduckgo.com', 'duckduckgo.com', 'www.youtube.com']);
let pulsed = null;
function pulses() {
  const rows = shown.activity;
  // What happened before this page opened has already travelled.
  if (pulsed === null) pulsed = rows.length;
  if (rows.length < pulsed) pulsed = 0;
  for (const { fact } of rows.slice(pulsed)) {
    switch (fact.kind) {
      case 'resolved': pulse('vm>dns'); break;
      case 'request': pulse(SEARCH_HOSTS.has(fact.host) ? 'vm>search' : 'vm>sites'); break;
      case 'search': pulse('vm>search'); break;
      case 'no_route': pulse('vm>router'); break;
      case 'model_call': pulse('vm>calls', `calls>${fact.host}`); break;
      case 'egress':
        if (fact.phase !== 'attempt') break;
        if (fact.purpose === 'page writer') pulse(`writer>${fact.host}`);
        else if (fact.purpose === 'original') pulse('writer>originals');
        else if (fact.purpose === 'live_search') pulse(`search>${fact.host}`);
        else if (fact.purpose === 'live_capture') pulse('sites>copies');
        else if (fact.purpose === 'account') pulse(`signin>${fact.host}`);
        break;
    }
  }
  pulsed = rows.length;
}

const briefPath = (path) => path.split('?')[0];
const isAsset = (request) => /^(image\/|font\/|audio\/|video\/|text\/css|(?:text|application)\/(?:x-)?javascript|application\/(?:font|x-font|vnd\.ms-fontobject))/.test(request.content_type)
  || /\.(?:css|[cm]?js|map|ico|png|jpe?g|gif|svg|webp|avif|woff2?|ttf|otf|eot|mp[34]|webm)(?:\?|$)/i.test(request.path);
const isSubresource = (fact) => fact.fetch === 'subresource' || isAsset(fact);
const urlOf = (fact) => `${fact.scheme}://${fact.host}${fact.path}`;
// A page's own requests (stylesheets, scripts, XHR, third-party calls)
// belong to the page that asked for them, by the referrer it sent.
function pageRequests() {
  const groups = new Map(), pages = [];
  for (const row of shown.activity) {
    const fact = row.fact;
    if (fact.kind !== 'request') continue;
    if (!isSubresource(fact) || !pages.length) { pages.push(row); groups.set(row, []); continue; }
    const referrer = fact.referrer, origin = referrer && originOf(referrer);
    const parent = [...pages].reverse().find((page) => referrer && urlOf(page.fact) === referrer)
      || [...pages].reverse().find((page) => origin && originOf(urlOf(page.fact)) === origin)
      || [...pages].reverse().find((page) => page.fact.host === fact.host)
      || pages.at(-1);
    groups.get(parent).push(row);
  }
  return groups;
}
function hitHosts(hits) {
  const hosts = [...new Set(hits.map((hit) => hostOf(hit.url).replace(/^www\./, '')))];
  return hosts.slice(0, 3).join(', ') + (hosts.length > 3 ? ', …' : '');
}
function activityItem(row) {
  const fact = row.fact;
  switch (fact.kind) {
    case 'request': {
      const url = urlOf(fact), hit = hitFor(url);
      const document = /(?:text\/html|application\/pdf)/.test(fact.content_type);
      const thumbnail = document && fact.status < 400 && /text\/html/.test(fact.content_type) ? url : null;
      return { title: `${fact.status >= 400 ? 'Requested' : 'Opened'} ${fact.title || hit?.title || fact.host}`, meta: `${fact.host}${briefPath(fact.path) === '/' ? '' : briefPath(fact.path)} · ${fact.status} · ${sourceName(fact.source)}`, target: document ? `page:${url}` : `site:${fact.host}`, thumbnail };
    }
    case 'search': return { title: `Searched “${fact.query}”`, meta: fact.results.length ? `${quantity(fact.results.length, 'result')} · ${hitHosts(fact.results)}` : 'No results', target: 'search' };
    case 'tool': return { title: `${fact.tool === 'fetch' ? 'Fetched' : 'Searched'} ${fact.tool === 'fetch' ? fact.target : `“${fact.target}”`}`, meta: fact.error || (fact.tool === 'fetch' ? 'Answered by the world' : fact.results.length ? `${quantity(fact.results.length, 'result')} · ${hitHosts(fact.results)}` : 'No results'), target: 'calls' };
    case 'no_route': return { title: `Tried ${fact.to}`, meta: 'No route', target: 'router' };
  }
}
// Feed rows are keyed and kept, so a page's picture loads once.
const feedRows = new Map();
function feedRow(key, row, item, resources) {
  const signature = JSON.stringify([item, row.at_ms, resources.length]);
  const kept = feedRows.get(key);
  if (kept?.signature === signature) return kept.node;
  const node = element('div', undefined, `activity-row ${row.fact.kind}`);
  const open = button('', () => select(item.target), 'activity-open');
  open.title = `${item.title} · ${item.meta}`;
  open.append(element('span', stamp(row.at_ms), 'stamp'), element('span', item.title, 'activity-title'), element('span', item.meta, 'activity-meta'));
  const text = element('div', undefined, 'activity-text');
  text.append(open);
  node.append(text);
  const picture = kept?.node.querySelector('.thumbnail');
  if (item.thumbnail) {
    if (picture?.dataset.url === item.thumbnail) node.append(picture);
    else {
      const frame = element('div', undefined, 'thumbnail');
      frame.dataset.url = item.thumbnail;
      const view = element('iframe');
      view.setAttribute('sandbox', '');
      view.setAttribute('loading', 'lazy');
      view.setAttribute('tabindex', '-1');
      view.setAttribute('aria-hidden', 'true');
      view.referrerPolicy = 'no-referrer';
      view.src = `/thumbnail?${new URLSearchParams({ url: item.thumbnail })}`;
      frame.append(view);
      frame.addEventListener('click', () => select(item.target));
      node.append(frame);
    }
  }
  if (resources.length) {
    const group = element('details', undefined, 'page-assets');
    group.open = !!kept?.node.querySelector('details[open]');
    group.append(element('summary', quantity(resources.length, 'request')));
    for (const resource of resources) {
      const fact = resource.fact;
      const target = fact.host === row.fact.host ? fact.path : `${fact.host}${fact.path}`;
      group.append(button(`${target} · ${fact.status}`, () => select(`site:${fact.host}`), 'asset-row'));
    }
    text.append(group);
  }
  feedRows.set(key, { signature, node });
  return node;
}
function feed() {
  const groups = pageRequests();
  const rows = activityRows().filter((row) => ['request', 'search', 'tool', 'no_route'].includes(row.fact.kind) && (row.fact.kind !== 'request' || groups.has(row)));
  const keep = new Set();
  const nodes = rows.reverse().map((row) => {
    const fact = row.fact;
    const key = fact.kind === 'no_route' ? `no_route:${fact.from}:${fact.to}` : `${fact.kind}:${row.at_ms}:${fact.host || ''}${fact.path || ''}${fact.query || ''}${fact.target || ''}`;
    keep.add(key);
    return feedRow(key, row, activityItem(row), groups.get(row) || []);
  });
  for (const key of feedRows.keys()) if (!keep.has(key)) feedRows.delete(key);
  const list = $('activity');
  if (!nodes.length) {
    if (!list.querySelector('.feed-empty')) list.replaceChildren(element('p', 'No activity yet', 'feed-empty'));
    return;
  }
  list.querySelector('.feed-empty')?.remove();
  nodes.forEach((node, index) => { if (list.children[index] !== node) list.insertBefore(node, list.children[index] || null); });
  while (list.children.length > nodes.length) list.lastChild.remove();
}
function activityRows() {
  const attempts = new Map();
  for (const row of shown.activity) if (row.fact.kind === 'no_route') attempts.set(`${row.fact.from}:${row.fact.to}`, row);
  return shown.activity.filter((row) => {
    if (row.fact.kind !== 'no_route') return true;
    return attempts.get(`${row.fact.from}:${row.fact.to}`) === row;
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
function hitFor(url) {
  return shown.sites.flatMap((site) => site.searches.flatMap((search) => search.results)).concat(shown.calls.flatMap((call) => call.tools.flatMap((tool) => tool.results))).find((hit) => hit.url === url);
}
function results(hits) {
  const list = element('div');
  if (!hits.length) list.append(element('p', 'No results', 'world-answer'));
  for (const hit of hits) {
    const opened = requestFor(hit.url);
    const row = button('', () => select(`page:${hit.url}`), `result ${opened ? 'opened' : 'unopened'}`);
    row.append(element('span', hit.title || hit.url, 'result-title'), element('small', hit.url), element('span', opened ? opened.status >= 400 ? 'Failed' : 'Opened' : '', 'result-state'));
    if (opened?.status >= 400) row.classList.add('failed');
    list.append(row);
  }
  return list;
}
async function readPage(url, container) {
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
function egressRows(purpose) {
  return activityRows().filter((row) => row.fact.kind === 'egress' && row.fact.purpose === purpose && row.fact.phase !== 'attempt');
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
        else content.append(element('p', 'Answered by the world', 'world-answer'));
      }
      const row = element('div', undefined, 'detail-row'); row.append(element('span', stamp(call.at_ms), 'stamp'), content); body.append(row);
    }
  } else if (selection.startsWith('page:')) {
    const url = selection.slice(5), request = requestFor(url);
    const hit = hitFor(url);
    const served = shown.activity.findLast((row) => row.fact.kind === 'request' && urlOf(row.fact) === url)?.fact.title;
    heading(served || hit?.title || 'Page', url);
    body.append(element('p', request ? `${request.status >= 400 ? 'Failed' : 'Opened'} · ${request.status} · ${sourceName(request.source)}` : 'Not opened', 'page-state'));
    if (request?.has_preview) {
      const container = element('div', 'Loading page…', 'reading-view');
      body.append(container);
      readPage(url, container).catch((error) => { container.textContent = error.message; });
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
      body.append(detailRow(search.at_ms, 'Search', quantity(search.results.length, 'result'), content));
    }
    for (const request of site?.requests || []) {
      const content = element('details'), summary = element('summary'), data = element('dl');
      content.dataset.key = `${request.method}:${request.path}:${request.at_ms}`;
      content.open = expanded.has(content.dataset.key);
      summary.append(element('div', `${request.method} ${request.path}`, 'label'), element('div', `${request.status} · ${size(request.bytes)} · ${sourceName(request.source)}`, 'meta'));
      for (const [key, value] of [...request.headers, ['content-type', request.content_type], ['elapsed', request.elapsed_ms ? `${request.elapsed_ms} ms` : '<1 ms']]) data.append(element('dt', key), element('dd', value));
      content.append(summary, data);
      if (request.has_preview) content.append(button('Page', () => select(`page:${request.url}`), 'more'));
      const row = element('div', undefined, 'detail-row'); row.append(element('span', stamp(request.at_ms), 'stamp'), content); body.append(row);
    }
    if (!site?.requests.length && !site?.searches.length) body.append(element('p', 'Not opened', 'detail-empty'));
  } else if (selection === 'copies' || selection === 'originals') {
    const purpose = selection === 'copies' ? 'live_capture' : 'original';
    heading(selection === 'copies' ? 'Page copies' : 'Originals');
    if (selection === 'copies') {
      for (const site of shown.sites) for (const request of site.requests.filter((request) => request.source.kind === 'live' && request.status >= 200 && request.status < 300 && request.has_preview)) {
        body.append(button(request.url, () => select(`page:${request.url}`), 'site-list'));
      }
    }
    for (const row of egressRows(purpose)) body.append(detailRow(row.at_ms, row.fact.host, `${row.fact.method} ${row.fact.path} · ${row.fact.status || phaseName(row.fact.phase)}`));
    if (!body.childElementCount) body.append(element('p', 'No requests', 'detail-empty'));
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
      body.append(detailRow(search.at_ms, 'Search', quantity(search.results.length, 'result'), content));
    }
    if (!searches.length) body.append(element('p', 'No searches', 'detail-empty'));
  } else if (selection === 'writer') {
    heading('Page writer');
    for (const row of egressRows('page writer')) body.append(detailRow(row.at_ms, row.fact.host, `${row.fact.method} ${row.fact.path} · ${row.fact.status || phaseName(row.fact.phase)}`));
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
    if (!body.childElementCount) body.append(element('p', 'No lookups', 'detail-empty'));
  } else if (selection === 'router') {
    heading('Router', '10.0.0.1');
    for (const row of activityRows().filter((row) => row.fact.kind === 'no_route')) body.append(detailRow(row.at_ms, row.fact.to, 'No route'));
    if (!body.childElementCount) body.append(element('p', 'Nothing refused', 'detail-empty'));
  } else {
    heading('Workstation', hostStatus?.addresses.join(' · ') || '10.0.0.2');
    actions.append(button('Show agent', () => { select(null); $('agent').hidden = false; $('agent-toggle').setAttribute('aria-pressed', 'true'); }));
  }
  body.scrollTop = scroll;
}

function draw() {
  graph(); feed(); details();
  $('clock').textContent = stamp(shown.at_ms);
}
const stream = new EventSource('/state');
stream.onerror = () => { $('clock').title = 'Reconnecting'; };
stream.onopen = () => { $('clock').title = ''; };
stream.onmessage = (event) => {
  shown = JSON.parse(event.data);
  draw();
  pulses();
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
  $('terminal').hidden = kind !== 'terminal'; $('screen').classList.toggle('off', kind !== 'screen');
  // The workstation's screen is a phone: the pane takes its portrait shape.
  $('agent').classList.toggle('phone', kind === 'screen');
  $('terminal-tab').setAttribute('aria-pressed', String(kind === 'terminal'));
  $('screen-tab').setAttribute('aria-pressed', String(kind === 'screen'));
  const ready = kind === 'screen' ? hostStatus.screen : hostStatus.terminal;
  $('console-status').hidden = ready;
  $('console-status').textContent = hostStatus.state === 'failed' ? 'The workstation failed to start. See the process output.' : hostStatus.state === 'stopped' ? 'The workstation has stopped.' : 'Starting the workstation…';
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
      await document.fonts.load('15px "JetBrains Mono"');
      const ghostty = await library.Ghostty.load('/vendor/ghostty-web/dist/ghostty-vt.wasm');
      create = (socket) => component.mount($('terminal'), library, socket, { ghostty, fontSize: 15, fontFamily: 'JetBrains Mono', theme: { background: '#151917', foreground: '#dce2dc', cursor: '#dce2dc' } });
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
