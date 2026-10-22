import { createMotion } from './motion.mjs';
import { ENGINES, ENGINE_HOSTS, engine, queryTag, pageTag, short, hostOf, hostMark, layout, siteKey } from './model.mjs';

const cut = (text, size) => text.length > size ? `${text.slice(0, size - 1)}…` : text;

export function createWeb(svg, { el, motion = createMotion(svg.ownerDocument.defaultView || globalThis) }) {
  const add = (tag, attrs, parent = svg) => el(`svg:${tag}`, attrs, parent);
  const attrs = (node, values) => {
    for (const [key, value] of Object.entries(values)) node.setAttribute(key, value);
  };
  let previous = null;
  const waitingSites = new Set();
  const making = new Map();
  const window = svg.ownerDocument.defaultView || globalThis;
  const later = window.setTimeout?.bind(window) || globalThis.setTimeout;
  const cancel = window.clearTimeout?.bind(window) || globalThis.clearTimeout;
  let latestSnapshot, requests = [];
  const names = new Map(), representatives = new Map(), openedHosts = new Set();
  const layers = {};
  for (const name of ['edges', 'links', 'sites', 'engines', 'top', 'marks', 'fx']) layers[name] = add('g', { class: `layer-${name}` });
  const keyed = (parent, make, update, remove = (node) => node.remove()) => {
    const nodes = new Map();
    return (items) => {
      const keys = new Set(items.map(([key]) => key));
      for (const [key, node] of nodes) if (!keys.has(key)) { remove(node); nodes.delete(key); }
      items.forEach(([key, value], index) => {
        let node = nodes.get(key);
        if (!node) { node = make(parent); nodes.set(key, node); }
        update(node, value);
        if (parent.children[index] !== node) parent.insertBefore(node, parent.children[index] || null);
      });
    };
  };
  add('rect', { class: 'query', x: 24, y: 18, width: 472, height: 34, rx: 17 }, layers.top);
  const browser = add('g', { class: 'glyph-browser', transform: 'translate(42 35)' }, layers.top);
  add('rect', { x: -7, y: -6, width: 14, height: 12, rx: 2.5 }, browser);
  add('line', { x1: -7, y1: -2, x2: 7, y2: -2 }, browser);
  add('circle', { cx: -4.5, cy: -4, r: .9 }, browser);
  const agent = add('text', { class: 'glyph-agent', x: 42, y: 40, 'text-anchor': 'middle' }, layers.top);
  const caret = add('rect', { class: 'caret', x: 60, y: 27, width: 1.5, height: 16 }, layers.top);
  const words = add('text', { class: 'query-text', x: 60, y: 40 }, layers.top);
  const queryTitle = add('title', {}, layers.top);
  const engines = ENGINES.map((name, index) => {
    const x = [110, 260, 410][index];
    const edge = add('line', { x1: 260, y1: 52, x2: x, y2: 94 }, layers.edges);
    const group = add('g', { class: 'engine-group', 'data-engine': name }, layers.engines);
    const mark = hostMark(`${name}.com`);
    group.style.setProperty('--app-host-color', mark.color);
    add('circle', { class: 'breathing', cx: x, cy: 108, r: 12, 'aria-hidden': 'true' }, group);
    const node = add('circle', { cx: x, cy: 108, r: 12 }, group);
    add('text', { class: 'mark', x, y: 108, 'aria-hidden': 'true', text: mark.letter }, group);
    add('text', { class: 'label', x, y: 84, 'text-anchor': 'middle', text: engine(name) }, group);
    const halo = add('circle', { class: 'halo', cx: x, cy: 108, r: 17 }, group);
    return { name, x, edge, node, halo };
  });
  const resultLayer = add('g', { class: 'result-lines' }, layers.edges);
  const results = keyed(resultLayer, (parent) => add('g', { class: 'result-group' }, parent), (group, line) => {
    let node = group.firstChild;
    if (!node) node = add('line', { class: 'result' }, group);
    attrs(node, line);
  });
  const links = keyed(layers.links, (parent) => {
    const group = add('g', { class: 'link-group' }, parent);
    add('path', { class: 'link' }, group);
    add('path', { class: 'arrowhead' }, group);
    return group;
  }, (group, { url, from: [x, y], to: [tx, ty] }) => {
    attrs(group, { 'data-url': url });
    const dx = tx - x, dy = ty - y, length = Math.hypot(dx, dy);
    const bend = length * .18;
    const cx = (x + tx) / 2 - dy / length * bend, cy = (y + ty) / 2 + dx / length * bend;
    const angle = Math.atan2(ty - cy, tx - cx);
    const ex = tx - Math.cos(angle) * 19, ey = ty - Math.sin(angle) * 19;
    attrs(group.children[0], { d: `M ${x} ${y} Q ${cx} ${cy} ${ex} ${ey}` });
    attrs(group.children[1], { d: `M ${ex - 6 * Math.cos(angle - .5)} ${ey - 6 * Math.sin(angle - .5)} L ${ex} ${ey} L ${ex - 6 * Math.cos(angle + .5)} ${ey - 6 * Math.sin(angle + .5)}` });
  });
  const sites = keyed(layers.sites, (parent) => {
    const group = add('g', { class: 'site-group' }, parent);
    add('circle', {}, group);
    const label = add('text', { class: 'label small', 'text-anchor': 'middle' }, group);
    add('title', {}, group);
    group.dots = keyed(add('g', { class: 'page-dots' }, group), (p) => {
      const g = add('g', { class: 'page-group' }, p);
      add('circle', {}, g);
      add('circle', { class: 'page-ring' }, g);
      add('title', {}, g);
      return g;
    }, (g, { page, index, r, x, y }) => {
      const angle = -Math.PI / 2 + index * Math.PI / 4.5;
      const pos = { cx: x + (r + 8) * Math.cos(angle), cy: y + (r + 8) * Math.sin(angle) };
      attrs(g, { 'data-url': page.url });
      attrs(g.children[0], { ...pos, r: 3.6, class: `page ${page.making ? 'making' : pageTag(page)}` });
      attrs(g.children[1], { ...pos, r: 6.5, visibility: page.carries > 0 ? 'visible' : 'hidden' });
      g.children[2].textContent = page.url;
    });
    add('text', { class: 'mark', 'aria-hidden': 'true' }, group);
    return group;
  }, (g, { host, site, x, y, pages, scenario, visit }) => {
    const count = pages.filter((p) => p.fetches > 0).length + (visit?.outcome.status === 'served' ? 1 : 0);
    const r = count ? 9 + Math.min(count - 1, 4) * 1.25 : 8;
    const mark = hostMark(siteKey(host));
    const latest = [...pages].sort((a, b) => a.at_ms - b.at_ms || (a.seq ?? 0) - (b.seq ?? 0)).at(-1);
    const state = visit && (!latest || (visit.answer_at_ms ?? visit.at_ms) >= latest.at_ms) ? queryTag(latestSnapshot, visit) : latest ? pageTag(latest) : 'listed';
    attrs(g, { 'data-host': host, class: `site-group ${count ? 'opened' : 'listed'}` });
    g.style.setProperty('--app-host-color', mark.color);
    attrs(g.children[4], { x, y, 'font-size': count ? Math.min(r * 1.3, 17) : 10 });
    g.children[4].textContent = mark.letter;
    g.style.transformOrigin = `${x}px ${y}px`;
    attrs(g.children[0], { class: `site ${state}${scenario ? ' scenario' : ''}${pages.some((p) => p.making) || making.has(siteKey(host)) ? ' making' : ''}`, cx: x, cy: y, r });
    attrs(g.children[1], { x, y: y + r + 18 });
    const label = g.children[1];
    label.replaceChildren();
    let rest = short(site);
    for (let line = 0; line < 2 && rest; line++) {
      const span = add('tspan', { x, dy: line ? 13 : 0, text: rest }, label);
      const width = () => span.getComputedTextLength?.() || span.textContent.length * 6.5;
      if (width() <= 116) break;
      let end = rest.length;
      while (end > 1 && width() > 116) {
        end--;
        span.textContent = rest.slice(0, end) + (line ? '…' : '');
      }
      const space = rest.lastIndexOf(' ', end);
      if (!line && space > 0) {
        span.textContent = rest.slice(0, space + 1);
        rest = rest.slice(space + 1);
      } else {
        if (!line) {
          // A name with no space to wrap at is cut, never broken mid-word.
          while (end > 1 && (span.textContent = `${rest.slice(0, end)}…`, width() > 116)) end--;
        }
        rest = '';
      }
    }
    g.children[2].textContent = host;
    g.dots(pages.map((page, index) => [page.url, { page, index, r, x, y }]));
  }, (node) => {
    if (!motion.active) { node.remove(); return; }
    layers.fx.append(node);
    node.setAttribute('data-transient', '');
    motion.removeAfter(node, motion.anim(node, [{ opacity: 1 }, { opacity: 0 }], { duration: 320 }));
  });
  const current = add('circle', { class: 'current', visibility: 'hidden', 'aria-label': 'Current site', cx: 0, cy: 0, r: 0 }, layers.top);
  const refused = add('g', { class: 'refused-mark' }, layers.marks);
  add('circle', { class: 'refused', cx: 24, cy: 540, r: 9 }, refused);
  add('path', { class: 'cross', d: 'M 18 534 L 30 546 M 30 534 L 18 546' }, refused);
  const refusedName = add('text', { class: 'label refused', x: 40, y: 544 }, refused);
  const refusedTitle = add('title', {}, refused);
  const planted = add('g', { class: 'planted-mark' }, layers.marks);
  add('path', { class: 'diamond', d: 'M 488 533 L 495 540 L 488 547 L 481 540 Z' }, planted);
  const fact = add('text', { class: 'label planted', x: 472, y: 544, 'text-anchor': 'end' }, planted);
  const factTitle = add('title', {}, planted);
  function fitFact() {
    const split = refused.getAttribute('visibility') === 'visible';
    const text = split ? factTitle.textContent : cut(factTitle.textContent, 70);
    fact.replaceChildren();
    const width = split ? 220 : 448;
    const lines = split ? 2 : 1;
    let rest = text;
    for (let i = 0; i < lines && rest; i++) {
      const line = add('tspan', { x: 472, y: split ? 532 + i * 16 : 544, text: rest }, fact);
      let end = rest.length;
      while (end > 1 && (line.getComputedTextLength?.() ?? line.textContent.length * 6) > width) {
        end--;
        line.textContent = rest.slice(0, end) + (i === lines - 1 ? '…' : '');
      }
      if (end < rest.length && i < lines - 1) {
        const space = rest.lastIndexOf(' ', end);
        if (space > 0) end = space + 1;
        line.textContent = rest.slice(0, end);
      }
      rest = rest.slice(end).trimStart();
    }
  }
  const ResizeObserver = svg.ownerDocument.defaultView?.ResizeObserver;
  const size = ResizeObserver ? new ResizeObserver(fitFact) : null;
  size?.observe(svg);
  planted.children[0].style.transformOrigin = '488px 540px';
  function render(snapshot, changes = null) {
    latestSnapshot = snapshot;
    const latest = snapshot.queries.at(-1);
    const query = snapshot.queries.findLast((q) => ENGINES.includes(q.engine));
    if (!motion.typingRemaining(words)) words.textContent = cut(latest?.search || '', 54);
    queryTitle.textContent = latest?.search || '';
    const claude = ['claude_web_search', 'codex_web_search'].includes(latest?.via);
    attrs(browser, { visibility: claude ? 'hidden' : 'visible' });
    agent.textContent = claude ? '❯' : '';
    attrs(caret, { visibility: latest ? 'hidden' : 'visible' });
    for (const e of engines) {
      const asked = query && snapshot.queries.findLast((q) => q.engine === e.name && q.key === query.key);
      const state = asked ? queryTag(snapshot, asked) : 'idle';
      attrs(e.node, { class: `engine ${state}` });
      attrs(e.node.parentNode, { class: `engine-group ${asked?.outcome.status === 'pending' ? 'asking' : asked?.outcome.status === 'served' ? 'answered' : 'idle'}` });
      attrs(e.edge, { class: `ask ${query?.engine === e.name ? 'live' : 'idle'}` });
      attrs(e.halo, { visibility: asked?.carries > 0 ? 'visible' : 'hidden' });
    }
    const listed = query?.outcome.status === 'pending' ? []
      : [...(snapshot.results.find((r) => r.key === query?.key)?.listed || [])].sort((a, b) => a.rank - b.rank);
    const remember = (host, site) => {
      const key = siteKey(host);
      if (!representatives.has(key)) representatives.set(key, host);
      if (site) names.set(key, site);
      return key;
    };
    for (const row of snapshot.seed.sites) remember(row.host, row.site);
    const offMap = snapshot.queries.filter((q) => !ENGINES.includes(q.engine));
    for (const q of offMap) remember(ENGINE_HOSTS[q.engine] || q.engine, engine(q.engine));
    for (const row of snapshot.sites || []) remember(row.host, row.site);
    for (const list of snapshot.results) for (const row of list.listed) remember(row.host, row.site);
    for (const row of snapshot.pages) remember(row.host, row.site);
    const hosts = new Set(snapshot.seed.sites.map((row) => remember(row.host, row.site)));
    for (const q of offMap) {
      const host = remember(ENGINE_HOSTS[q.engine] || q.engine);
      if (q.outcome.status === 'served') openedHosts.add(host);
      hosts.add(host);
    }
    const recent = snapshot.queries.filter((q) => ENGINES.includes(q.engine)).slice(-2);
    const recentKeys = new Set(recent.map((q) => q.key));
    if (!recent.length) for (const result of snapshot.results.slice(-2)) recentKeys.add(result.key);
    for (const list of snapshot.results.filter((r) => recentKeys.has(r.key))) for (const row of list.listed) hosts.add(remember(row.host, row.site));
    for (const p of snapshot.pages) {
      const host = remember(p.host, p.site);
      hosts.add(host);
      if (p.fetches > 0) openedHosts.add(host);
      if (p.reason?.via === 'link') openedHosts.add(remember(hostOf(p.reason.from)));
    }
    for (const host of openedHosts) hosts.add(host);
    const scenario = snapshot.seed.sites.map((row) => siteKey(row.host));
    const map = layout(previous, [...hosts], { seed: { sites: scenario } });
    if (changes && motion.active && query && (query.outcome.status === 'pending' || changes.some((c) => c.type === 'search_answered' && c.query.id === query.id))) {
      for (const host of map.assignment.keys()) if (!previous?.assignment.has(host) && !offMap.some((q) => siteKey(ENGINE_HOSTS[q.engine] || q.engine) === host)) waitingSites.add(host);
    }
    for (const host of waitingSites) if (!map.assignment.has(host)) waitingSites.delete(host);
    previous = map;
    const pages = (host) => snapshot.pages.filter((p) => siteKey(p.host) === host).sort((a, b) => (a.first_serve_ms ?? a.at_ms) - (b.first_serve_ms ?? b.at_ms) || a.url.localeCompare(b.url));
    sites([...map.assignment].map(([host, [x, y]]) => [host, { host: representatives.get(host) || host, site: names.get(host) || host, x, y, pages: pages(host), scenario: scenario.includes(host), visit: offMap.findLast((q) => siteKey(ENGINE_HOSTS[q.engine] || q.engine) === host) }]));
    if (!motion.active) waitingSites.clear();
    for (const group of layers.sites.children) {
      group.style.opacity = waitingSites.has(siteKey(group.getAttribute('data-host'))) ? '0' : '';
    }
    const asked = engines.find((e) => e.name === query?.engine);
    results(asked ? listed.filter((r) => map.assignment.has(siteKey(r.host))).map((r) => {
      const [x, y] = map.assignment.get(siteKey(r.host));
      return [`${query.id}:${r.rank}:${r.url}`, { x1: asked.x, y1: 121, x2: x, y2: y - (pages(siteKey(r.host)).some((p) => p.fetches > 0) ? 16 : 7), 'data-rank': r.rank }];
    }) : []);
    links(snapshot.pages.filter((p) => p.reason?.via === 'link' && siteKey(hostOf(p.reason.from)) !== siteKey(p.host) && map.assignment.has(siteKey(hostOf(p.reason.from))) && map.assignment.has(siteKey(p.host))).map((p) => [p.url, { url: p.url, from: map.assignment.get(siteKey(hostOf(p.reason.from))), to: map.assignment.get(siteKey(p.host)) }]));
    locate(snapshot);
    const refusal = snapshot.refused.filter((r) => !r.name.startsWith('_')).at(-1);
    attrs(refused, { visibility: refusal ? 'visible' : 'hidden' });
    refusedName.textContent = cut(refusal?.name || '', 22);
    refusedTitle.textContent = refusal?.name || '';
    const plant = snapshot.planted.filter((p) => p.kind === 'fact').at(-1);
    attrs(planted, { visibility: plant ? 'visible' : 'hidden' });
    factTitle.textContent = plant?.text || '';
    fitFact();
  }
  function locate(snapshot) {
    const lastPage = snapshot.pages.filter((p) => p.fetches > 0).sort((a, b) => a.at_ms - b.at_ms || (a.seq ?? 0) - (b.seq ?? 0)).at(-1);
    const request = requests.filter((e) => snapshot.pages.some((p) => p.fetches > 0 && siteKey(p.host) === siteKey(e.fields.host) && e.at * 1000 >= p.at_ms)).sort((a, b) => a.at - b.at || a.seq - b.seq).at(-1);
    const pageAt = request ? request.at * 1000 : lastPage?.at_ms;
    const pageHost = request?.fields.host || lastPage?.host;
    const lastQuery = snapshot.queries.filter((q) => q.outcome.status === 'served').sort((a, b) => (a.answer_at_ms ?? a.at_ms) - (b.answer_at_ms ?? b.at_ms) || (a.answer_seq ?? a.seq ?? 0) - (b.answer_seq ?? b.seq ?? 0)).at(-1);
    const queryIsLatest = lastQuery && (pageAt == null || (lastQuery.answer_at_ms ?? lastQuery.at_ms) > pageAt);
    const target = queryIsLatest ? queryTarget(lastQuery) : pageHost && siteNode(pageHost)?.children[0];
    if (target) attrs(current, { cx: target.getAttribute('cx'), cy: target.getAttribute('cy'), r: Number(target.getAttribute('r')) + 4, visibility: 'visible' });
    else {
      attrs(current, { visibility: 'hidden' });
      attrs(current, { cx: 0, cy: 0, r: 0 });
    }
  }
  const position = (node) => [Number(node.getAttribute('cx')), Number(node.getAttribute('cy'))];
  const siteNode = (host) => [...layers.sites.children].find((g) => siteKey(g.getAttribute('data-host')) === siteKey(host));
  const queryTarget = (q) => engines.find((e) => e.name === q?.engine)?.node || (q && siteNode(ENGINE_HOSTS[q.engine] || q.engine)?.children[0]);
  const pageNode = (url) => [...svg.querySelectorAll('.page-group')].find((g) => g.getAttribute('data-url') === url);
  const fade = (node, duration, delay = 0) => motion.anim(node, [{ opacity: 0 }, { opacity: 1 }], { duration, delay });
  function outline(node, duration, delay = 0) {
    const length = 2 * Math.PI * Number(node.getAttribute('r'));
    motion.anim(node, [
      { strokeDasharray: `${length}`, strokeDashoffset: length, fillOpacity: 0 },
      { strokeDasharray: `${length}`, strokeDashoffset: 0, fillOpacity: 0, offset: .7 },
      { strokeDasharray: `${length}`, strokeDashoffset: 0, fillOpacity: 1 },
    ], { duration, delay, easing: 'cubic-bezier(.4,0,.2,1)' });
  }
  function animate(changes, snapshot, oldHosts) {
    const current = snapshot.queries.at(-1);
    const mapQuery = snapshot.queries.findLast((q) => ENGINES.includes(q.engine));
    const threadDelay = changes.some((c) => c.type === 'fact_reached') ? 300 : 0;
    for (const group of layers.sites.children) if (!oldHosts.has(siteKey(group.getAttribute('data-host'))) && !waitingSites.has(siteKey(group.getAttribute('data-host')))) {
      motion.anim(group, [{ opacity: 0, transform: 'scale(.6)' }, { opacity: 1, transform: 'scale(1)' }], { duration: 320, easing: 'cubic-bezier(.2,.9,.3,1.2)' });
    }
    for (const change of changes) {
      const e = engines.find((e) => e.name === change.query?.engine);
      if (change.type === 'search_started' && change.query.id === current?.id) {
        motion.typeInto(words, cut(current.search, 54), Math.min(600, current.search.length * 28));
        const target = queryTarget(current);
        if (target) motion.travel(layers.fx, [260, 52], position(target), ['claude_web_search', 'codex_web_search'].includes(current.via) ? 'agent' : 'ink', 300);
      }
      if (change.type === 'search_answered' && (e ? change.query.key === mapQuery?.key : change.query.id === current?.id)) {
        const target = queryTarget(change.query);
        if (!target) continue;
        const [x, y] = position(target);
        const delay = change.query.id === current?.id ? motion.typingRemaining(words) : 0;
        if (change.state === 'made') outline(target, 520, delay);
        else if (change.state === 'again') {
          motion.ring(layers.fx, x, y, 'again', 20, 500, delay);
          motion.ring(layers.fx, x, y, 'again', 26, 560, delay + 140);
        } else if (change.state === 'stored') motion.ring(layers.fx, x, y, 'stored', 18, 420, delay);
        target.style.transformOrigin = `${x}px ${y}px`;
        motion.pulse(target, delay);
        if (e && change.query.id === mapQuery.id) {
          const reveal = delay + 380 + threadDelay;
          for (const group of layers.sites.children) {
            const host = siteKey(group.getAttribute('data-host'));
            if (!waitingSites.has(host)) continue;
            const rank = change.list.find((r) => siteKey(r.host) === host)?.rank || 1;
            motion.anim(group, [{ opacity: 0, transform: 'scale(.6)' }, { opacity: 1, transform: 'scale(1)' }], { duration: 320, delay: reveal + (rank - 1) * 36, easing: 'cubic-bezier(.2,.9,.3,1.2)' });
            waitingSites.delete(host);
            group.style.opacity = '';
          }
          for (const g of resultLayer.children) motion.drawIn(g.firstChild, 240, reveal + Math.max(0, Number(g.firstChild.getAttribute('data-rank')) - 1) * 36);
        }
      }
      if (change.type === 'page_opened' || change.type === 'page_again') {
        const p = change.page, site = siteNode(p.host), group = pageNode(p.url);
        if (!site || !group) continue;
        const dot = group.children[0], [x, y] = position(dot), [sx, sy] = position(site.children[0]);
        if (change.type === 'page_again') {
          motion.ring(layers.fx, x, y, 'again', 14, 480);
          motion.ring(layers.fx, sx, sy, 'again', Number(site.children[0].getAttribute('r')) + 10, 520, 120);
        } else if (change.state === 'made') {
          outline(dot, 640);
        } else {
          fade(dot, 160);
          motion.ring(layers.fx, x, y, change.state, 14, 420);
          motion.pulse(site);
        }
        if (change.type === 'page_opened' && p.reason?.via === 'search') {
          const q = current?.search === p.reason.query || current?.key === p.reason.query ? current : null;
          const engine = engines.find((e) => e.name === q?.engine);
          if (engine) motion.travel(layers.fx, [engine.x, 121], [sx, sy - Number(site.children[0].getAttribute('r')) - 2], p.via === 'web_fetch' ? 'agent' : 'ink', 300);
        }
        if (change.type === 'page_opened' && p.reason?.via === 'link') {
          const link = [...layers.links.children].find((g) => g.getAttribute('data-url') === p.url);
          if (siteKey(hostOf(p.reason.from)) === siteKey(p.host)) {
            motion.travel(layers.fx, [sx, sy - Number(site.children[0].getAttribute('r')) - 2], [x, y], p.via === 'web_fetch' ? 'agent' : 'ink', 520);
          } else if (link) {
            motion.drawIn(link.children[0], 520);
            fade(link.children[1], 100, 420);
            motion.travel(layers.fx, link.children[0], null, p.via === 'web_fetch' ? 'agent' : 'ink', 520);
          }
        }
      }
      if (change.type === 'plant' && change.plant.kind === 'fact') {
        motion.anim(planted.children[0], [{ transform: 'scale(0)', opacity: 0 }, { transform: 'scale(1.35)', opacity: 1, offset: .6 }, { transform: 'scale(1)', opacity: 1 }], { duration: 480, easing: 'cubic-bezier(.3,.7,.3,1)' });
        motion.ring(layers.fx, 488, 540, 'planted', 30, 700);
        fade(fact, 300, 200);
      }
      if (change.type === 'refused') {
        motion.anim(refused, [0, -3, 3, -2, 0].map((x) => ({ transform: `translate(${x}px, 0)` })), { duration: 360 });
        motion.ring(layers.fx, 24, 540, 'refused', 24, 520);
        fade(refusedName, 200);
      }
      if (change.type === 'fact_reached') {
        const target = change.kind === 'query' ? queryTarget(change.target) : pageNode(change.target.url)?.children[0];
        if (!target || (change.kind === 'query' && change.target.id !== current?.id)) continue;
        const [x, y] = position(target);
        const path = add('path', { class: 'thread', 'data-transient': '', d: `M 488 540 Q ${(488 + x) / 2 + 40} ${(540 + y) / 2} ${x} ${y}` }, layers.fx);
        motion.drawIn(path, 420);
        motion.travel(layers.fx, path, null, 'planted', 440);
        motion.ring(layers.fx, x, y, 'planted', 24, 640, 440);
        motion.removeAfter(path, motion.anim(path, [{ opacity: 1 }, { opacity: 1, offset: 2920 / 3520 }, { opacity: 0 }], { duration: 3520 }));
      }
    }
  }
  const stopMotion = motion.subscribe((disabled) => {
    if (!disabled) return;
    waitingSites.clear();
    for (const group of layers.sites.children) group.style.opacity = '';
  });
  return {
    setEvents(events) {
      requests = events.filter((e) => e.source === 'http' && e.kind === 'request' && e.fields?.kind === 'page');
      if (latestSnapshot) locate(latestSnapshot);
    },
    apply(changes, snapshot) {
      if (changes.some((c) => c.type === 'restart')) { this.reset(snapshot); return; }
      motion.suppressed = changes.length > 8;
      const oldHosts = new Set(previous?.assignment.keys() || []);
      if (motion.active && changes.some((c) => c.type === 'search_started' && c.query.id === snapshot.queries.at(-1)?.id && ENGINES.includes(c.query.engine))) {
        for (const group of resultLayer.children) {
          const line = group.firstChild;
          const old = add('line', Object.fromEntries(['x1', 'y1', 'x2', 'y2', 'class'].map((key) => [key, line.getAttribute(key)])), layers.fx);
          old.setAttribute('data-transient', '');
          motion.removeAfter(old, motion.anim(old, [{ opacity: .28 }, { opacity: 0 }], { duration: 380 }));
        }
      }
      for (const change of changes) if (window.document && !window.document.hidden && change.type === 'page_opened' && change.state === 'made') {
        const key = siteKey(change.page.host);
        cancel(making.get(key));
        making.set(key, later(() => {
          making.delete(key);
          const site = siteNode(key)?.children[0];
          if (site && !latestSnapshot.pages.some((p) => siteKey(p.host) === key && p.making)) {
            site.setAttribute('class', site.getAttribute('class').replace(/ making/g, ''));
          }
        }, 900));
      }
      render(snapshot, changes);
      if (motion.active) animate(changes, snapshot, oldHosts);
      else if (motion.reduced && changes.length <= 8 && !svg.ownerDocument.hidden) {
        for (const change of changes) {
          const target = change.type === 'page_again' ? pageNode(change.page.url)?.children[0]
            : change.type === 'search_answered' && change.state === 'again' && change.query.key === snapshot.queries.at(-1)?.key
              ? queryTarget(change.query) : null;
          if (target) motion.ring(layers.fx, ...position(target), 'again', change.type === 'page_again' ? 14 : 20, 150);
        }
      }
    },
    reset(snapshot) {
      motion.suppressed = true;
      for (const timer of making.values()) cancel(timer);
      making.clear();
      previous = null;
      waitingSites.clear();
      names.clear(); representatives.clear(); openedHosts.clear();
      render(snapshot);
      // Apply the reset before radius transitions resume.
      svg.getBoundingClientRect();
      motion.suppressed = false;
    },
    dispose() { for (const timer of making.values()) cancel(timer); making.clear(); size?.disconnect(); stopMotion(); motion.dispose(); svg.replaceChildren(); },
  };
}
