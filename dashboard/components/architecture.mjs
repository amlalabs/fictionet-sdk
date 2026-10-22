// Fixed positions; every count and pulse comes from observations.
import { scoped, listen } from '../dom.mjs';
import { pageGraph } from '../visibility.mjs';

export function architecture(state, hosts, declarations) {
  const graph = pageGraph(state, hosts);
  const vm = hosts.map((host) => {
    const nodes = new Set([...graph.nodes.values()].filter((node) => node.kind === 'sandbox' && node.name === (host.sandbox || host.name)).map((node) => node.id));
    const links = [...graph.edges.values()].filter((edge) => nodes.has(edge.a) || nodes.has(edge.b));
    return { title: host.name, column: 0, programs: [host.claude_code && 'Claude Code', host.codex && 'Codex', host.firefox && 'Firefox', host.terminal && 'Terminal'].filter(Boolean), links: links.map((edge) => edge.id), count: links.reduce((n, edge) => n + (edge.c?.[0] || 0) + (edge.c?.[2] || 0), 0), events: graph.events.filter((event) => (event.sandbox?.name || event.sandbox) === (host.sandbox || host.name)).slice(-3).reverse().map((event) => event.summary || event.kind) };
  });
  const services = declarations.map((service) => {
    const events = graph.events.filter((event) => event.source === service.source && (!service.kinds.length || service.kinds.includes(event.kind)));
    const nodes = new Set(events.map((event) => event.node).filter(Boolean));
    const addresses = new Set(events.flatMap((event) => [event.local, event.peer]).filter(Boolean).map((value) => value.replace(/:\d+$/, '')));
    const links = [...graph.edges.values()].filter((edge) => nodes.has(edge.a) || nodes.has(edge.b) || [graph.nodes.get(edge.a), graph.nodes.get(edge.b)].some((node) => node?.addresses?.some((address) => addresses.has(address))));
    return { title: service.title, column: service.outside ? 2 : 1, links: links.map((edge) => edge.id), records: events, pairs: events.filter((event) => event.local && event.peer).map((event) => [event.local, event.peer]), count: events.length, events: events.slice(-3).reverse().map((event) => String(event.fields?.[service.detail] ?? event.kind)), pair: events.at(-1) };
  });
  return [...vm, ...services];
}

export function mount(root, services) {
  const { el } = scoped(root);
  root.classList.add('architecture');
  const columns = ['VM', 'The world', 'Real internet'].map((title) => {
    const column = el('section', { class: 'architecture-column' }, root);
    el('h2', { text: title }, column);
    return column;
  });
  el('span', { class: 'architecture-in', text: '→', 'aria-hidden': 'true' }, root);
  const crossing = el('div', { class: 'architecture-out' }, root);
  el('span', { text: 'Models · Sign-in' }, crossing);
  el('span', { text: '→', 'aria-hidden': 'true' }, crossing);
  const boxes = new Map(), animations = new Set(), cleanup = [];
  let outside = 0;
  function pulse(element) {
    if (!element.animate || root.ownerDocument.defaultView?.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const animation = element.animate([{ opacity: 0.45 }, { opacity: 1 }], { duration: 350 });
    animations.add(animation);
    animation.finished.then(() => animations.delete(animation), () => animations.delete(animation));
  }
  function render(name, data) {
    const rows = architecture(services.graph.state, services.hosts, services.architecture || []);
    let crossings = 0;
    rows.forEach((row, index) => {
      let box = boxes.get(index);
      if (!box) {
        const button = el('button', { type: 'button', class: 'architecture-box' }, columns[row.column]);
        el('strong', { text: row.title }, button);
        for (const text of row.programs || []) el('div', { text }, button);
        const count = el('span', { class: 'architecture-count' }, button);
        const lines = el('div', { class: 'architecture-events' }, button);
        box = { button, count, lines, value: 0, row };
        boxes.set(index, box);
        cleanup.push(listen(button, 'click', () => {
          services.selection.set({ host: row.column === 0 ? row.title : null, node: null, links: box.row.links, event: null, connection: null, request: null });
          services.packetPair.set(row.column === 0 ? null : { pairs: box.row.pairs, label: row.title });
          services.showPanel('packets');
        }));
      }
      if (name === 'event' && row.column !== 0) row.count = box.value + (row.records.includes(data) ? 1 : 0);
      else if (name !== 'snapshot' && row.column !== 0) row.count = box.value;
      if (name !== 'snapshot' && row.count > box.value) pulse(box.button);
      box.value = row.count;
      box.row = row;
      box.count.textContent = String(row.count);
      box.lines.replaceChildren(...row.events.map((text) => el('div', { text })));
      if (row.column === 2) crossings += row.count;
    });
    if (name !== 'snapshot' && crossings > outside) pulse(crossing);
    outside = crossings;
  }
  render('snapshot');
  const stop = services.graph.subscribe((name, data) => render(name, data));
  return () => { stop(); cleanup.forEach((off) => off()); animations.forEach((animation) => animation.cancel()); root.replaceChildren(); };
}
