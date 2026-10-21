import { createMotion } from './motion.mjs';
import { ENGINES, engine, queryTag, pageTag, short, hostOf, layout } from './model.mjs';

const cut = (text, size) => text.length > size ? `${text.slice(0, size - 1)}…` : text;

export function createWeb(svg, { el, motion = createMotion(svg.ownerDocument.defaultView || globalThis) }) {
  const add = (tag, attrs, parent = svg) => el(`svg:${tag}`, attrs, parent);
  const attrs = (node, values) => {
    for (const [key, value] of Object.entries(values)) node.setAttribute(key, value);
  };
  let previous = null;
  const layers = {};
  for (const name of ['edges', 'links', 'sites', 'engines', 'top', 'marks', 'fx']) layers[name] = add('g', { class: `layer-${name}` });
  const keyed = (parent, make, update) => {
    const nodes = new Map();
    return (items) => {
      const keys = new Set(items.map(([key]) => key));
      for (const [key, node] of nodes) if (!keys.has(key)) { node.remove(); nodes.delete(key); }
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
    const node = add('circle', { cx: x, cy: 108, r: 12 }, group);
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
    return group;
  }, (g, { host, x, y, pages, scenario }) => {
    const r = 8 + Math.min(pages.filter((p) => p.fetches > 0).length, 4) * 1.5;
    const latest = [...pages].sort((a, b) => a.at_ms - b.at_ms || (a.seq ?? 0) - (b.seq ?? 0)).at(-1);
    const state = latest ? pageTag(latest) : 'listed';
    attrs(g, { 'data-host': host });
    g.style.transformOrigin = `${x}px ${y}px`;
    attrs(g.children[0], { class: `site ${state}${scenario ? ' scenario' : ''}${pages.some((p) => p.making) ? ' making' : ''}`, cx: x, cy: y, r });
    attrs(g.children[1], { x, y: y + r + 18 });
    g.children[1].textContent = short(host);
    g.children[2].textContent = host;
    g.dots(pages.map((page, index) => [page.url, { page, index, r, x, y }]));
  });
  const more = add('text', { class: 'label small', x: 500, y: 158, 'text-anchor': 'end' }, layers.marks);
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
    fact.textContent = cut(factTitle.textContent, 40);
    if (!fact.getComputedTextLength?.()) return;
    fact.textContent = factTitle.textContent;
    while (fact.textContent.length > 1 && fact.getComputedTextLength() > 252) {
      fact.textContent = `${fact.textContent.replace(/…$/, '').slice(0, -1)}…`;
    }
  }
  const ResizeObserver = svg.ownerDocument.defaultView?.ResizeObserver;
  const size = ResizeObserver ? new ResizeObserver(fitFact) : null;
  size?.observe(svg);
  planted.children[0].style.transformOrigin = '488px 540px';
  function render(snapshot, changes = null) {
    const query = snapshot.queries.at(-1);
    words.textContent = cut(query?.search || '', 54);
    queryTitle.textContent = query?.search || '';
    const claude = query?.via === 'web_search';
    attrs(browser, { visibility: claude ? 'hidden' : 'visible' });
    agent.textContent = claude ? '❯' : '';
    attrs(caret, { visibility: query ? 'hidden' : 'visible' });
    for (const e of engines) {
      const asked = query && snapshot.queries.findLast((q) => q.engine === e.name && q.key === query.key);
      attrs(e.node, { class: `engine ${asked ? queryTag(snapshot, asked) : 'idle'}` });
      attrs(e.edge, { class: `ask ${query?.engine === e.name ? 'live' : 'idle'}` });
      attrs(e.halo, { visibility: asked?.carries > 0 ? 'visible' : 'hidden' });
    }
    const listed = query?.outcome.status === 'pending' ? []
      : [...(snapshot.results.find((r) => r.key === query?.key)?.listed || [])].sort((a, b) => a.rank - b.rank);
    const hosts = new Set(snapshot.seed?.sites || []);
    const touched = new Map();
    for (const list of [...snapshot.results].sort((a, b) => a.query_id - b.query_id)) for (const row of list.listed) hosts.add(row.host);
    for (const p of snapshot.pages) {
      hosts.add(p.host); touched.set(p.host, p.at_ms);
      if (p.reason?.via === 'link') hosts.add(hostOf(p.reason.from));
    }
    const opened = changes ? changes.filter((c) => c.page).map((c) => c.page) : snapshot.pages;
    const map = layout(previous, [...hosts], { seed: snapshot.seed, list: listed, opened, touched });
    previous = map;
    const pages = (host) => snapshot.pages.filter((p) => p.host === host).sort((a, b) => (a.first_serve_ms ?? a.at_ms) - (b.first_serve_ms ?? b.at_ms) || a.url.localeCompare(b.url));
    sites([...map.assignment].map(([host, [x, y]]) => [host, { host, x, y, pages: pages(host), scenario: snapshot.seed?.sites.includes(host) }]));
    const asked = engines.find((e) => e.name === query?.engine);
    results(asked ? listed.filter((r) => map.assignment.has(r.host)).map((r) => {
      const [x, y] = map.assignment.get(r.host);
      return [`${query.id}:${r.rank}:${r.url}`, { x1: asked.x, y1: 121, x2: x, y2: y - 10 - Math.min(pages(r.host).filter((p) => p.fetches > 0).length, 4) * 1.5, 'data-rank': r.rank }];
    }) : []);
    links(snapshot.pages.filter((p) => p.reason?.via === 'link' && hostOf(p.reason.from) !== p.host && map.assignment.has(hostOf(p.reason.from)) && map.assignment.has(p.host)).map((p) => [p.url, { url: p.url, from: map.assignment.get(hostOf(p.reason.from)), to: map.assignment.get(p.host) }]));
    more.textContent = map.hidden ? `+${map.hidden}` : '';
    const refusal = snapshot.refused.filter((r) => !r.name.startsWith('_')).at(-1);
    attrs(refused, { visibility: refusal ? 'visible' : 'hidden' });
    refusedName.textContent = cut(refusal?.name || '', 22);
    refusedTitle.textContent = refusal?.name || '';
    const plant = snapshot.planted.filter((p) => p.kind === 'fact').at(-1);
    attrs(planted, { visibility: plant ? 'visible' : 'hidden' });
    factTitle.textContent = plant?.text || '';
    fitFact();
  }
  const position = (node) => [Number(node.getAttribute('cx')), Number(node.getAttribute('cy'))];
  const siteNode = (host) => [...layers.sites.children].find((g) => g.getAttribute('data-host') === host);
  const pageNode = (url) => [...svg.querySelectorAll('.page-group')].find((g) => g.getAttribute('data-url') === url);
  const fade = (node, duration, delay = 0) => motion.anim(node, [{ opacity: 0 }, { opacity: 1 }], { duration, delay });
  function outline(node, duration) {
    const length = 2 * Math.PI * Number(node.getAttribute('r'));
    motion.anim(node, [
      { strokeDasharray: `${length}`, strokeDashoffset: length, fillOpacity: 0 },
      { strokeDasharray: `${length}`, strokeDashoffset: 0, fillOpacity: 0, offset: .7 },
      { strokeDasharray: `${length}`, strokeDashoffset: 0, fillOpacity: 1 },
    ], { duration, easing: 'cubic-bezier(.4,0,.2,1)' });
  }
  function animate(changes, snapshot, oldHosts) {
    const current = snapshot.queries.at(-1);
    for (const group of layers.sites.children) if (!oldHosts.has(group.getAttribute('data-host'))) {
      motion.anim(group, [{ opacity: 0, transform: 'scale(.6)' }, { opacity: 1, transform: 'scale(1)' }], { duration: 320, easing: 'cubic-bezier(.2,.9,.3,1.2)' });
    }
    for (const change of changes) {
      const e = engines.find((e) => e.name === change.query?.engine);
      if (change.type === 'search_started' && change.query.id === current?.id) {
        motion.typeInto(words, cut(current.search, 54));
        motion.travel(layers.fx, [260, 52], [e.x, 94], current.via === 'web_search' ? 'agent' : 'ink', 300);
      }
      if (change.type === 'search_answered' && change.query.key === current?.key) {
        if (change.state === 'made') outline(e.node, 520);
        else if (change.state === 'again') {
          motion.ring(layers.fx, e.x, 108, 'again', 20, 500);
          motion.ring(layers.fx, e.x, 108, 'again', 26, 560, 140);
        } else if (change.state === 'stored') motion.ring(layers.fx, e.x, 108, 'stored', 18, 420);
        if (change.query.id === current.id) [...resultLayer.children].forEach((g) => motion.drawIn(g.firstChild, 240, Math.max(0, Number(g.firstChild.getAttribute('data-rank')) - 1) * 36));
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
          motion.anim(site.children[0], [{ strokeDasharray: '3 3' }, { strokeDasharray: '3 3' }], { duration: 640 });
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
          if (hostOf(p.reason.from) === p.host) {
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
        const target = change.kind === 'query' ? engines.find((e) => e.name === change.target.engine)?.node : pageNode(change.target.url)?.children[0];
        if (!target || (change.kind === 'query' && change.target.key !== current?.key)) continue;
        const [x, y] = position(target);
        const path = add('path', { class: 'thread', 'data-transient': '', d: `M 488 540 Q ${(488 + x) / 2 + 40} ${(540 + y) / 2} ${x} ${y}` }, layers.fx);
        motion.drawIn(path, 420);
        motion.travel(layers.fx, path, null, 'planted', 440);
        motion.ring(layers.fx, x, y, 'planted', 24, 640, 440);
        motion.removeAfter(path, motion.anim(path, [{ opacity: 1 }, { opacity: 1, offset: .6 }, { opacity: 0 }], { duration: 1400 }));
      }
    }
  }
  return {
    apply(changes, snapshot) {
      if (changes.some((c) => c.type === 'restart')) { this.reset(snapshot); return; }
      motion.suppressed = changes.length > 8;
      const oldHosts = new Set(previous?.assignment.keys() || []);
      if (motion.active && changes.some((c) => c.type === 'search_started' && c.query.id === snapshot.queries.at(-1)?.id)) {
        for (const group of resultLayer.children) {
          const line = group.firstChild;
          const old = add('line', Object.fromEntries(['x1', 'y1', 'x2', 'y2', 'class'].map((key) => [key, line.getAttribute(key)])), layers.fx);
          old.setAttribute('data-transient', '');
          motion.removeAfter(old, motion.anim(old, [{ opacity: .28 }, { opacity: 0 }], { duration: 380 }));
        }
      }
      render(snapshot, changes);
      if (motion.active) animate(changes, snapshot, oldHosts);
      else if (motion.reduced && changes.length <= 8 && !svg.ownerDocument.hidden) {
        for (const change of changes) {
          const target = change.type === 'page_again' ? pageNode(change.page.url)?.children[0]
            : change.type === 'search_answered' && change.state === 'again' && change.query.key === snapshot.queries.at(-1)?.key
              ? engines.find((e) => e.name === change.query.engine)?.node : null;
          if (target) motion.ring(layers.fx, ...position(target), 'again', change.type === 'page_again' ? 14 : 20, 150);
        }
      }
    },
    reset(snapshot) {
      motion.suppressed = true;
      previous = null;
      render(snapshot);
      // Apply the reset before radius transitions resume.
      svg.getBoundingClientRect();
      motion.suppressed = false;
    },
    dispose() { size?.disconnect(); motion.dispose(); svg.replaceChildren(); },
  };
}
