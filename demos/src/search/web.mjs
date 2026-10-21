import { ENGINES, engine, queryTag, pageTag, short, hostOf, layout } from './model.mjs';

const cut = (text, size) => text.length > size ? `${text.slice(0, size - 1)}…` : text;

export function createWeb(svg, { el }) {
  const add = (tag, attrs, parent = svg) => el(`svg:${tag}`, attrs, parent);
  const attrs = (node, values) => {
    for (const [key, value] of Object.entries(values)) node.setAttribute(key, value);
  };
  const layers = {};
  for (const name of ['edges', 'links', 'sites', 'engines', 'top', 'marks']) layers[name] = add('g', { class: `layer-${name}` });
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
  }, (group, { from: [x, y], to: [tx, ty] }) => {
    const dx = tx - x, dy = ty - y, length = Math.hypot(dx, dy);
    if (!length) {
      attrs(group.children[0], { d: `M ${x + 12} ${y - 10} C ${x + 44} ${y - 26} ${x + 44} ${y + 22} ${x + 12} ${y + 6}` });
      attrs(group.children[1], { d: `M ${x + 19} ${y + 5} L ${x + 12} ${y + 6} L ${x + 15} ${y + 12}` });
      return;
    }
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
      attrs(g.children[0], { ...pos, r: 3.6, class: `page ${page.making ? 'making' : pageTag(page)}` });
      attrs(g.children[1], { ...pos, r: 6.5, visibility: page.carries > 0 ? 'visible' : 'hidden' });
      g.children[2].textContent = page.url;
    });
    return group;
  }, (g, { host, x, y, pages, scenario }) => {
    const r = 8 + Math.min(pages.filter((p) => p.fetches > 0).length, 4) * 1.5;
    const state = pages.length ? pageTag(pages.at(-1)) : 'listed';
    attrs(g, { 'data-host': host });
    attrs(g.children[0], { class: `site ${state}${scenario ? ' scenario' : ''}${pages.some((p) => p.making) ? ' making' : ''}`, cx: x, cy: y, r });
    attrs(g.children[1], { x, y: y + r + 14 });
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
  const fact = add('text', { class: 'label planted', x: 472, y: 544, 'text-anchor': 'end', textLength: 252, lengthAdjust: 'spacingAndGlyphs' }, planted);
  const factTitle = add('title', {}, planted);
  function render(snapshot) {
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
    const listed = [...(snapshot.results.find((r) => r.key === query?.key)?.listed || [])].sort((a, b) => a.rank - b.rank);
    const hosts = new Set(snapshot.seed?.sites || []);
    const touched = new Map();
    for (const list of snapshot.results) for (const row of list.listed) hosts.add(row.host);
    for (const p of snapshot.pages) {
      hosts.add(p.host); touched.set(p.host, p.at_ms);
      if (p.reason?.via === 'link') hosts.add(hostOf(p.reason.from));
    }
    const map = layout(null, [...hosts], { seed: snapshot.seed, list: listed, opened: snapshot.pages, touched });
    const pages = (host) => snapshot.pages.filter((p) => p.host === host).sort((a, b) => (a.first_serve_ms ?? a.at_ms) - (b.first_serve_ms ?? b.at_ms) || a.url.localeCompare(b.url));
    sites([...map.assignment].map(([host, [x, y]]) => [host, { host, x, y, pages: pages(host), scenario: snapshot.seed?.sites.includes(host) }]));
    const asked = engines.find((e) => e.name === query?.engine);
    results(asked ? listed.filter((r) => map.assignment.has(r.host)).map((r) => {
      const [x, y] = map.assignment.get(r.host);
      return [`${query.id}:${r.rank}:${r.url}`, { x1: asked.x, y1: 121, x2: x, y2: y - 10 - Math.min(pages(r.host).filter((p) => p.fetches > 0).length, 4) * 1.5, 'data-rank': r.rank }];
    }) : []);
    links(snapshot.pages.filter((p) => p.reason?.via === 'link' && map.assignment.has(hostOf(p.reason.from)) && map.assignment.has(p.host)).map((p) => [p.url, { from: map.assignment.get(hostOf(p.reason.from)), to: map.assignment.get(p.host) }]));
    more.textContent = map.hidden ? `+${map.hidden}` : '';
    const refusal = snapshot.refused.filter((r) => !r.name.startsWith('_')).at(-1);
    attrs(refused, { visibility: refusal ? 'visible' : 'hidden' });
    refusedName.textContent = cut(refusal?.name || '', 22);
    refusedTitle.textContent = refusal?.name || '';
    const plant = snapshot.planted.filter((p) => p.kind === 'fact').at(-1);
    attrs(planted, { visibility: plant ? 'visible' : 'hidden' });
    fact.textContent = cut(plant?.text || '', 40);
    factTitle.textContent = plant?.text || '';
    attrs(fact, { textLength: Math.min(252, fact.textContent.length * 6.3) });
  }
  return {
    apply(changes, snapshot) { if (changes.some((c) => c.type === 'restart')) this.reset(snapshot); else render(snapshot); },
    reset: render,
    dispose() { svg.replaceChildren(); },
  };
}
