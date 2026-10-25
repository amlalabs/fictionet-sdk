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
const sourceName = (source) => source.kind === 'copy' ? source.captured ? `Copied ${source.captured.slice(0, 10)}` : 'Copied' : ({ edited: 'Edited', package: 'Package' })[source.kind] || 'Live';
const changes = (edits) => edits?.length ? quantity(edits.length, 'change') : null;
const hostName = (name) => name.replace(/\.$/, '');
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
  if (key) showAgent(true);
  draw();
  // Back on the feed, the newest rows are in view: they arrive at the top.
  if (!key) $('activity').scrollTop = 0;
}
$('close-details').onclick = () => select(null);
function showAgent(shown) {
  $('agent').hidden = !shown;
  document.body.classList.toggle('agent-hidden', !shown);
  $('agent-toggle').setAttribute('aria-pressed', String(shown));
  $('agent-toggle').textContent = shown ? 'Hide agent' : 'Show agent';
}
$('agent-toggle').onclick = () => showAgent($('agent').hidden);
const UPSTREAM = ['model', 'account', 'editor'];
function localSites() {
  const upstream = new Set([...shown.connections.filter((row) => UPSTREAM.includes(row.purpose)).map((row) => row.host), ...shown.calls.map((call) => call.host)]);
  return shown.sites.filter((site) => !upstream.has(site.host));
}
const purposeName = (purpose) => ({ model: 'Model', editor: 'Editor', account: 'Sign-in', live_search: 'Search', live_capture: 'Page copy', package: 'Package' })[purpose];
const phaseName = (phase) => ({ connecting: 'Connecting', receiving: 'Receiving', streaming: 'Streaming', complete: 'Complete', interrupted: 'Interrupted', attempt: 'Connecting', response: 'Received', failed: 'Failed' })[phase];

// The network map is built once; each state only changes its text, its
// destinations and, when the layout moves, its wires. Each internet host
// appears once, with a wire from every service that reached it.
const SERVICES = [
  { id: 'dns', title: 'DNS' },
  { id: 'search', title: 'Search', purposes: ['live_search'] },
  { id: 'sites', title: 'Sites', purposes: ['live_capture', 'package'] },
  { id: 'calls', title: 'Model gateway', purposes: ['model'] },
  { id: 'editor', title: 'Editor', purposes: ['editor'] },
  { id: 'signin', title: 'Sign-in', purposes: ['account'] },
  { id: 'router', title: 'Router' },
];
const map = { lanes: null, wires: null, pulses: null, vm: null, internet: null, services: new Map(), signature: '', destinations: '' };
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
  const services = element('div', undefined, 'services');
  map.internet = element('div', undefined, 'destinations');
  lanes.append(world, internet, map.wires, map.vm, services, map.internet);
  for (const service of SERVICES) {
    const control = button('', () => select(service.id), 'service unused');
    control.dataset.service = service.id;
    const title = element('strong', service.title), detail = element('small', '');
    control.append(title, detail);
    services.append(control);
    map.services.set(service.id, { ...service, control, detail });
  }
  lanes.append(map.pulses);
  root.replaceChildren(lanes);
  map.lanes = lanes;
}
// Host fetches for a page's own files belong to that page.
const pageFetches = (purpose) => shown.egress.filter((row) => row.fact.purpose === purpose && row.fact.phase !== 'attempt' && !row.fact.page);
// The pages the workstation opened on the world's sites, each address once.
// Package files count on their own row. Those that came from the internet
// (Live and Edited) are the pages the host copied, so Sites and Page copies
// count the same pages.
const openedRequests = () => localSites().flatMap((site) => site.requests.filter((request) => !isSubresource(request) && !SEARCH_HOSTS.has(site.host) && request.source.kind !== 'package'));
const openedPages = () => new Set(openedRequests().map((request) => request.url));
const copiedPages = () => new Set(openedRequests().filter((request) => ['live', 'edited'].includes(request.source.kind)).map((request) => request.url));
function graph() {
  if (!map.lanes) buildMap();
  map.vm.querySelector('small').textContent = hostStatus?.addresses[0] || '10.0.0.2';
  map.vm.setAttribute('aria-pressed', String(selection === 'workstation'));
  const sites = localSites();
  const pages = openedPages().size;
  const facts = shown.activity.map((row) => row.fact);
  const searches = shown.sites.flatMap((site) => site.searches).length + shown.calls.flatMap((call) => call.tools.filter((tool) => tool.tool === 'web_search')).length;
  const edits = editorCalls().length;
  const refusedTo = facts.filter((fact) => fact.kind === 'no_route').at(-1)?.to;
  const state = {
    dns: { detail: '10.0.0.1', reached: facts.some((fact) => fact.kind === 'resolved') },
    search: { detail: searches ? quantity(searches, 'search', 'searches') : '', reached: searches > 0 },
    sites: { detail: pages ? quantity(pages, 'page') : '', reached: sites.some((site) => site.requests.length) },
    calls: { detail: shown.calls.length ? quantity(shown.calls.length, 'call') : '', reached: shown.calls.length > 0 },
    editor: { detail: edits ? quantity(edits, 'call') : '', reached: edits > 0 },
    signin: { detail: shown.signin?.fact.open ? 'Open' : 'Closed', reached: false },
    router: { detail: refusedTo ? `No route to ${refusedTo}` : '', reached: !!refusedTo, refused: !!refusedTo },
  };
  for (const service of map.services.values()) {
    const { detail, reached, refused } = state[service.id];
    const purposes = service.purposes || [];
    const used = reached || shown.connections.some((row) => purposes.includes(row.purpose));
    service.control.className = `service ${used ? 'used' : 'unused'}${refused ? ' refused' : ''}`;
    service.control.dataset.reached = String(reached);
    service.control.setAttribute('aria-pressed', String(selection === service.id));
    if (service.detail.textContent !== detail) service.detail.textContent = detail;
  }
  const destinations = destinationsOf();
  const signature = JSON.stringify(destinations.map(({ key, title, meta, from }) => [key, title, meta, from, selection]));
  if (signature !== map.destinations) {
    map.destinations = signature;
    map.internet.replaceChildren(...destinations.map(({ key, title, meta, target, from }) => {
      const node = button('', () => select(target), 'destination');
      node.dataset.key = key;
      node.dataset.from = from.join(' ');
      node.setAttribute('aria-pressed', String(selection === target));
      node.append(element('strong', title));
      if (meta) node.append(element('small', meta));
      return node;
    }));
  }
  const layout = layoutSignature();
  if (layout !== map.signature) drawWires();
}
// Wires follow where their ends are: a scrollbar or a font that arrives
// late moves the boxes without resizing the map.
function layoutSignature() {
  const origin = map.lanes.getBoundingClientRect();
  const at = (node) => { const rect = node.getBoundingClientRect(); return [Math.round(rect.left - origin.left), Math.round(rect.top - origin.top), Math.round(rect.width)]; };
  return JSON.stringify([...map.services.values()].map((service) => [service.control.dataset.reached, at(service.control)]).concat([map.destinations, at(map.vm), [...map.internet.children].map(at), map.lanes.clientWidth, map.lanes.clientHeight]));
}
document.fonts?.ready.then(() => { if (map.lanes) { map.signature = ''; drawWires(); } });
// One row per internet destination, in service order: a host the world
// reached for a service, or the pages and package files it copied.
const COPIES = { live_capture: { target: 'copies', title: 'Page copies', unit: 'page' }, package: { target: 'packages', title: 'Packages', unit: 'file' } };
function destinationsOf() {
  const rows = new Map();
  for (const service of map.services.values()) {
    for (const purpose of service.purposes || []) {
      const hosts = [...new Set(shown.connections.filter((row) => row.purpose === purpose).map((row) => row.host))];
      if (!hosts.length) continue;
      const copies = COPIES[purpose];
      if (copies) {
        const copied = purpose === 'live_capture' ? copiedPages().size : new Set(pageFetches(purpose).map((row) => row.fact.path)).size;
        rows.set(copies.target, { key: copies.target, target: copies.target, title: copies.title, meta: quantity(copied, copies.unit), from: [service.id] });
      } else {
        for (const host of hosts) {
          const row = rows.get(host) || { key: host, target: `egress:${host}`, title: host, meta: '', from: [] };
          if (!row.from.includes(service.id)) row.from.push(service.id);
          rows.set(host, row);
        }
      }
    }
  }
  return [...rows.values()];
}
// Every wire is one path from its start to its end, so a pulse can travel it.
function drawWires() {
  const lanes = map.lanes;
  if (!lanes?.clientWidth) return;
  map.signature = layoutSignature();
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
  const starts = new Set();
  for (const node of map.internet.children) {
    const end = point(node, 'left');
    for (const id of node.dataset.from.split(' ')) {
      const service = map.services.get(id);
      if (!service) continue;
      const start = point(service.control, 'right');
      starts.add(service);
      wire(`${id}>${node.dataset.key}`, route(start, { x: end.x + 4, y: end.y }, start.x + (end.x - start.x) / 2));
    }
  }
  for (const service of starts) {
    const start = point(service.control, 'right');
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
      case 'certificate': pulse('vm>sites'); break;
      case 'model_call': pulse('vm>calls', `calls>${fact.host}`); break;
      case 'egress':
        if (fact.phase !== 'attempt') break;
        if (fact.purpose === 'editor') pulse('vm>editor', `editor>${fact.host}`);
        else if (fact.purpose === 'live_search') pulse(`search>${fact.host}`);
        else if (fact.purpose === 'live_capture' && !fact.page) pulse('sites>copies');
        else if (fact.purpose === 'package') pulse('sites>packages');
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
    if (!isSubresource(fact)) { pages.push(row); groups.set(row, []); continue; }
    // A file no page in the feed asked for stays with its site.
    if (!pages.length) continue;
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
      const where = `${fact.host}${briefPath(fact.path) === '/' ? '' : briefPath(fact.path)}`;
      if (fact.status >= 400) {
        const outcome = [404, 410].includes(fact.status) ? 'not found' : [502, 503, 504].includes(fact.status) ? 'unreachable' : 'failed';
        return { title: `${outcome === 'unreachable' ? fact.host : where} ${outcome}`, meta: [fact.status, sourceName(fact.source), fact.error].filter(Boolean).join(' · '), target: `site:${fact.host}`, failed: true };
      }
      const document = /(?:text\/html|application\/pdf)/.test(fact.content_type);
      // Package indexes and files are not pages: they get no picture.
      const thumbnail = document && fact.status < 400 && /text\/html/.test(fact.content_type) && fact.source.kind !== 'package' ? url : null;
      // A page that took a while says how long: a client with a deadline may have stopped waiting.
      const took = fact.elapsed_ms >= 1000 ? `${Math.round(fact.elapsed_ms / 1000)} s` : null;
      return { title: `${fact.status >= 400 ? 'Requested' : 'Opened'} ${fact.title || hit?.title || fact.host}`, meta: [where, fact.status, sourceName(fact.source), changes(fact.edits), took].filter(Boolean).join(' · '), target: document ? `page:${url}` : `site:${fact.host}`, thumbnail, edits: fact.edits };
    }
    case 'search': return { title: `Searched “${fact.query}”`, meta: fact.results.length ? [quantity(fact.results.length, 'result'), hitHosts(fact.results), changes(fact.edits)].filter(Boolean).join(' · ') : 'No results', target: 'search', edits: fact.edits };
    case 'tool': return { title: `${fact.tool === 'fetch' ? 'Fetched' : 'Searched'} ${fact.tool === 'fetch' ? fact.target : `“${fact.target}”`}`, meta: fact.error || (fact.tool === 'fetch' ? 'Answered by the world' : fact.results.length ? [quantity(fact.results.length, 'result'), hitHosts(fact.results), changes(fact.edits)].filter(Boolean).join(' · ') : 'No results'), target: 'calls', edits: fact.edits };
    case 'abandoned': {
      const where = `${fact.host}${briefPath(fact.path) === '/' ? '' : briefPath(fact.path)}`;
      return { title: `${where} timed out`, meta: `Agent stopped waiting after ${Math.round(fact.elapsed_ms / 1000)} s · ${sourceName(fact.source)}`, target: `site:${fact.host}`, failed: true };
    }
    case 'no_route': return { title: `Tried ${fact.to}`, meta: 'No route', target: 'router' };
    case 'certificate': return { title: `${hostName(fact.host)} certificate ${CERTIFICATE[fact.problem]}`, meta: `TLS · ${sourceName(fact.source)}`, target: `site:${hostName(fact.host)}`, failed: true };
    case 'resolved': return { title: `${hostName(fact.name)} not found`, meta: 'No address', target: 'dns', failed: true };
  }
}
// How a real site's certificate fails, as the feed says it.
const CERTIFICATE = { expired: 'expired', not_yet_valid: 'not yet valid', wrong_name: 'for another name', untrusted: 'not trusted' };
// A change reads as the real words struck through, then the world's words.
function changeList(edits, limit = edits.length) {
  const list = element('div', undefined, 'changes');
  for (const edit of edits.slice(0, limit)) {
    const row = element('div', undefined, 'change');
    row.append(element('del', edit.passage), element('ins', edit.replacement));
    list.append(row);
  }
  if (edits.length > limit) list.append(element('div', `${edits.length - limit} more`, 'change-more'));
  return list;
}
// Feed rows are keyed and kept, so a page's picture loads once.
const feedRows = new Map();
function feedRow(key, row, item, resources) {
  const signature = JSON.stringify([item, row.at_ms, resources.length]);
  const kept = feedRows.get(key);
  if (kept?.signature === signature) return kept.node;
  const node = element('div', undefined, `activity-row ${row.fact.kind}${item.failed ? ' failed' : ''}${item.retried ? ' retried' : ''}${item.edits?.length ? ' edited' : ''}`);
  const open = button('', () => select(item.target), 'activity-open');
  open.title = `${item.title} · ${item.meta}`;
  open.append(element('span', stamp(row.at_ms), 'stamp'), element('span', item.title, 'activity-title'), element('span', item.meta, 'activity-meta'));
  const text = element('div', undefined, 'activity-text');
  text.append(open);
  if (item.edits?.length) text.append(changeList(item.edits, 2));
  node.append(text);
  const picture = kept?.node.querySelector('.thumbnail');
  if (item.thumbnail) {
    if (picture?.dataset.url === item.thumbnail) node.append(picture);
    else {
      const frame = element('div', undefined, 'thumbnail');
      frame.dataset.url = item.thumbnail;
      const view = element('iframe');
      // Scripts are allowed only so the frame loads images as they come into
      // view: the picture has none, and its policy runs none.
      view.setAttribute('sandbox', 'allow-scripts');
      view.setAttribute('loading', 'lazy');
      view.setAttribute('tabindex', '-1');
      view.setAttribute('aria-hidden', 'true');
      view.referrerPolicy = 'no-referrer';
      view.src = `/thumbnail?${new URLSearchParams({ url: item.thumbnail, picture: 'feed' })}`;
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
// A client that stops waiting for a page and asks for it again makes one
// page visit, not several: requests for one address that were waiting at
// the same time, or that come next after one the client gave up on, share
// a row. The row shows the whole wait and how many times the page was
// asked for. A later visit to the same page, after other activity, is its
// own row.
function visits(rows, groups) {
  const startOf = (row) => row.at_ms - (row.fact.elapsed_ms || 0);
  const open = new Map(), shown = [];
  for (const row of [...rows].sort((a, b) => startOf(a) - startOf(b))) {
    const fact = row.fact;
    if (!['request', 'abandoned'].includes(fact.kind)) { shown.push({ row, attempts: [row] }); continue; }
    const key = `${fact.method} ${urlOf(fact)}`, visit = open.get(key);
    const waiting = visit && startOf(row) < visit.end;
    const askedAgain = visit?.gaveUp && shown.at(-1) === visit;
    if (waiting || askedAgain) {
      visit.attempts.push(row);
      visit.end = Math.max(visit.end, row.at_ms);
      visit.gaveUp = fact.kind === 'abandoned';
      continue;
    }
    const fresh = { attempts: [row], end: row.at_ms, gaveUp: fact.kind === 'abandoned' };
    open.set(key, fresh);
    shown.push(fresh);
  }
  return shown.map(({ attempts }) => {
    const [row] = attempts;
    if (attempts.length === 1) return { row, attempts, resources: groups.get(row) || [] };
    // The row reads as the page's last answer, or the last time the client gave up.
    const answered = attempts.filter((attempt) => attempt.fact.kind === 'request').at(-1) || attempts.at(-1);
    const first = Math.min(...attempts.map(startOf)), last = Math.max(...attempts.map((attempt) => attempt.at_ms));
    return { row: { ...answered, at_ms: last }, attempts, waited: last - first, resources: attempts.flatMap((attempt) => groups.get(attempt) || []) };
  }).sort((a, b) => a.row.at_ms - b.row.at_ms);
}
function feed() {
  const groups = pageRequests();
  const rows = activityRows().filter((row) => ['request', 'abandoned', 'search', 'tool', 'no_route', 'resolved', 'certificate'].includes(row.fact.kind) && (row.fact.kind !== 'request' || groups.has(row)) && (row.fact.kind !== 'abandoned' || !isSubresource(row.fact)) && (row.fact.kind !== 'resolved' || !row.fact.address));
  const keep = new Set();
  const nodes = visits(rows, groups).reverse().map(({ row, attempts, waited, resources }) => {
    const fact = attempts[0].fact, started = attempts[0].at_ms;
    const key = fact.kind === 'no_route' ? `no_route:${fact.from}:${fact.to}` : fact.kind === 'resolved' ? `resolved:${fact.name}` : fact.kind === 'certificate' ? `certificate:${fact.host}` : `${fact.kind}:${started}:${fact.host || ''}${fact.path || ''}${fact.query || ''}${fact.target || ''}`;
    keep.add(key);
    const item = activityItem(row);
    if (attempts.length > 1) {
      // Each earlier request was given up on: the client asked again.
      item.meta = [item.meta.replace(/ · \d+ s$/, ''), `asked ${attempts.length} times`, `waited ${Math.round(waited / 1000)} s`].join(' · ');
      item.retried = !item.failed;
    }
    return feedRow(key, row, item, resources);
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
// Repeated refusals and failed lookups of one name show once, at the latest.
function activityRows() {
  const keyOf = (fact) => fact.kind === 'no_route' ? `no_route:${fact.from}:${fact.to}` : fact.kind === 'resolved' && !fact.address ? `resolved:${fact.name}` : fact.kind === 'certificate' ? `certificate:${fact.host}` : null;
  const latest = new Map();
  for (const row of shown.activity) { const key = keyOf(row.fact); if (key) latest.set(key, row); }
  return shown.activity.filter((row) => { const key = keyOf(row.fact); return !key || latest.get(key) === row; });
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
// The page as the world served it, as the workstation's phone browser laid it
// out: its own markup, styles and images, with no scripts.
function servedPage(url) {
  const frame = element('iframe', undefined, 'recorded-page');
  // As in the feed: scripts are allowed only for images that load in view.
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.referrerPolicy = 'no-referrer';
  frame.title = url;
  frame.src = `/thumbnail?${new URLSearchParams({ url, picture: 'reading' })}`;
  return frame;
}
function egressRows(purpose) {
  return activityRows().filter((row) => row.fact.kind === 'egress' && row.fact.purpose === purpose && row.fact.phase !== 'attempt');
}
function editorCalls() {
  return egressRows('editor');
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
        if (tool.edits?.length) content.append(changeList(tool.edits));
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
    body.append(element('p', request ? [request.status >= 400 ? 'Failed' : 'Opened', request.status, sourceName(request.source), changes(request.edits)].filter(Boolean).join(' · ') : 'Not opened', 'page-state'));
    if (request?.edits.length) body.append(changeList(request.edits));
    if (request?.has_preview) {
      const container = element('div', undefined, 'reading-view');
      container.append(servedPage(request.url));
      body.append(container);
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
  } else if (selection === 'copies' || selection === 'packages') {
    const purpose = selection === 'copies' ? 'live_capture' : 'package';
    heading(selection === 'copies' ? 'Page copies' : 'Packages');
    // Each page the host fetched, with the files it fetched for that page.
    const files = new Map();
    for (const row of egressRows(purpose)) if (row.fact.page) files.set(row.fact.page, [...(files.get(row.fact.page) || []), row]);
    for (const row of egressRows(purpose).filter((row) => !row.fact.page)) {
      const own = files.get(row.fact.path) || [];
      let content;
      if (own.length) {
        content = element('details', undefined, 'page-files');
        content.dataset.key = `files:${row.fact.path}`;
        content.open = expanded.has(content.dataset.key);
        content.append(element('summary', quantity(own.length, 'file')));
        for (const file of own) content.append(element('div', `${file.fact.path.replace(/^https?:\/\//, '')} · ${file.fact.status || phaseName(file.fact.phase)}`, 'asset-row'));
      }
      body.append(detailRow(row.at_ms, row.fact.path, `${row.fact.method} · ${row.fact.status || phaseName(row.fact.phase)}`, content));
    }
    if (!body.childElementCount) body.append(element('p', 'No requests', 'detail-empty'));
  } else if (['egress', 'signin'].includes(selection) || selection.startsWith('egress:')) {
    const accepts = (row) => selection === 'signin' ? row.purpose === 'account' : selection.startsWith('egress:') ? row.host === selection.slice(7) : true;
    const connections = shown.connections.filter(accepts), egress = shown.egress.filter((row) => accepts(row.fact) && row.fact.phase !== 'attempt' && !row.fact.page);
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
      const content = element('div'); content.append(element('p', search.query, 'tool-query'));
      if (search.edits?.length) content.append(changeList(search.edits));
      content.append(search.error ? element('p', search.error, 'world-answer') : results(search.results));
      body.append(detailRow(search.at_ms, 'Search', [quantity(search.results.length, 'result'), changes(search.edits)].filter(Boolean).join(' · '), content));
    }
    if (!searches.length) body.append(element('p', 'No searches', 'detail-empty'));
  } else if (selection === 'editor') {
    heading('Editor', world?.scenario?.text || '');
    // Every real page and result list the scenario changed, newest first.
    const edited = [
      ...shown.sites.flatMap((site) => site.requests.filter((request) => request.edits.length).map((request) => ({ at_ms: request.at_ms, label: hitFor(request.url)?.title || request.url, meta: request.url, edits: request.edits, target: `page:${request.url}` }))),
      ...shown.sites.flatMap((site) => site.searches.filter((search) => search.edits.length).map((search) => ({ at_ms: search.at_ms, label: `Results for “${search.query}”`, meta: '', edits: search.edits, target: 'search' }))),
      ...shown.calls.flatMap((call) => call.tools.filter((tool) => tool.edits.length).map((tool) => ({ at_ms: tool.at_ms, label: `Results for “${tool.target}”`, meta: 'Search tool', edits: tool.edits, target: 'search' }))),
    ].sort((a, b) => b.at_ms - a.at_ms);
    for (const page of edited) {
      const content = changeList(page.edits);
      content.append(button('Open', () => select(page.target), 'more'));
      body.append(detailRow(page.at_ms, page.label, page.meta, content));
    }
    if (!edited.length) body.append(element('p', world?.scenario ? 'No pages changed yet' : 'No scenario', 'detail-empty'));
    if (editorCalls().length) body.append(element('p', quantity(editorCalls().length, 'model call'), 'meta'));
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
    actions.append(button('Show agent', () => { select(null); showAgent(true); }));
  }
  body.scrollTop = scroll;
}

// The run clock is the host's clock, read from its replies, and ticks.
let hostOffset = 0;
function tick() { $('clock').textContent = new Date(Date.now() + hostOffset).toLocaleTimeString([], { hour12: false, timeZone: 'UTC' }); }
setInterval(tick, 1000);
function draw() {
  graph(); feed(); details();
  tick();
}
// One socket carries what the page shows (the run, the world's settings,
// the workstation) and the commands it sends, so none of it waits behind
// the pictures for a connection, however many tabs show the page.
let updates = null, asked = 0;
const waiting = new Map();
function connect() {
  const socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/updates`);
  socket.onopen = () => { $('clock').title = ''; };
  socket.onmessage = (event) => {
    const update = JSON.parse(event.data);
    if (update.kind === 'view') { shown = update.state; draw(); pulses(); }
    else if (update.kind === 'world') showWorld(update.state);
    else if (update.kind === 'host') showHost(update.state);
    else if (update.kind === 'reply') {
      const reply = waiting.get(update.id);
      waiting.delete(update.id);
      if (update.error) reply?.reject(new Error(update.error)); else reply?.resolve();
    }
  };
  socket.onclose = () => {
    $('clock').title = 'Reconnecting';
    for (const reply of waiting.values()) reply.reject(new Error('The page lost its connection to the world. Try again.'));
    waiting.clear();
    if (updates === socket) setTimeout(connect, 1000);
  };
  updates = socket;
}
connect();
async function loadWorld() {
  const response = await fetch('/world');
  if (!response.ok) throw new Error('Could not read the world settings');
  const date = Date.parse(response.headers.get('date'));
  if (date) hostOffset = date + 500 - Date.now();
  showWorld(await response.json());
}
// Whether the scenario's account is written yet, said briefly.
const READINESS = { preparing: 'Preparing scenario', ready: 'Scenario ready', failed: 'Scenario failed. Set it again.' };
function showWorld(next) {
  world = next;
  $('world-date').textContent = world.date;
  // The field keeps what is being typed; it shows the scenario in force otherwise.
  if (document.activeElement !== $('scenario')) $('scenario').value = world.scenario?.text || '';
  $('scenario-form').hidden = world.edited.kind !== 'available';
  const readiness = world.scenario?.readiness;
  for (const id of ['scenario-state', 'scenario-readiness']) {
    const state = $(id);
    state.hidden = !readiness || (id === 'scenario-state' && world.source !== 'edited');
    state.dataset.kind = readiness?.kind || '';
    state.textContent = readiness ? READINESS[readiness.kind] : '';
    state.title = readiness?.error || '';
  }
  if (selection === 'editor') details();
  for (const control of $('source').querySelectorAll('button')) {
    const availability = world[control.dataset.source];
    control.disabled = availability.kind !== 'available';
    control.setAttribute('aria-pressed', String(control.dataset.source === world.source));
    control.title = { no_captures: 'No captures', no_search_key: 'No search key', no_model_key: 'No model key' }[availability.reason] || '';
  }
}
$('world-toggle').onclick = () => { $('world-menu').hidden = !$('world-menu').hidden; $('world-toggle').setAttribute('aria-expanded', String(!$('world-menu').hidden)); };
document.addEventListener('click', (event) => { if (!$('world-menu').contains(event.target) && !$('world-toggle').contains(event.target)) { $('world-menu').hidden = true; $('world-toggle').setAttribute('aria-expanded', 'false'); } });
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') { $('world-menu').hidden = true; $('world-toggle').setAttribute('aria-expanded', 'false'); select(null); } });
// Sends a command on the socket; settles when the world has applied it,
// after the socket has brought the settings it changed.
function command(command) {
  $('world-error').textContent = '';
  if (updates?.readyState !== WebSocket.OPEN) return Promise.reject(new Error('The page is reconnecting to the world. Try again.'));
  const id = ++asked;
  const reply = new Promise((resolve, reject) => waiting.set(id, { resolve, reject }));
  updates.send(JSON.stringify({ id, command }));
  return reply;
}
for (const control of $('source').querySelectorAll('button')) {
  control.onclick = async () => {
    if (control.getAttribute('aria-pressed') === 'true') return;
    for (const control of $('source').querySelectorAll('button')) control.disabled = true;
    try { await command({ command: 'set_source', source: control.dataset.source }); }
    catch (error) { notice(error.message); }
    finally { if (world) showWorld(world); }
  };
}
async function setScenario(scenario) {
  for (const control of $('scenario-form').querySelectorAll('button')) control.disabled = true;
  try { await command({ command: 'set_scenario', scenario }); $('scenario').blur(); showWorld(world); }
  catch (error) { $('world-error').textContent = error.message; }
  finally { for (const control of $('scenario-form').querySelectorAll('button')) control.disabled = false; }
}
$('scenario-form').onsubmit = (event) => { event.preventDefault(); setScenario($('scenario').value); };
$('scenario').addEventListener('keydown', (event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); setScenario($('scenario').value); } });
$('scenario-clear').onclick = () => { $('scenario').value = ''; setScenario(''); };
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
function showHost(next) {
  const changed = JSON.stringify(next) !== JSON.stringify(hostStatus);
  hostStatus = next;
  if (changed) mountConsole();
}
loadWorld().then(() => mountConsole()).catch((error) => notice(error.message));
draw();
window.addEventListener('pageshow', (event) => { if (event.persisted && !updates) connect(); });
window.addEventListener('pagehide', () => { const socket = updates; updates = null; socket?.close(); for (const console of consoles.values()) { console.component.dispose(); console.socket.close(); } });
