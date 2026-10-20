// mount(root, services, options) returns dispose. Services provide transport and selection.
import { scoped, listen } from '../dom.mjs';
import { createGraph } from '../graph.mjs';
import { createInteraction } from '../interaction.mjs';
import { createLayout } from '../layout.mjs';
import { createState } from '../state.mjs';
import { createTables } from '../tables.mjs';
import { fmtDuration, fmtBytes, fmtCount, fmtRate, plural } from '../format.mjs';

export function mount(root, services, options = {}) {
  const { $, el } = scoped(root);
  if (!$('stage')) structure(root, el);
  const reducedMotion = services.reducedMotion || matchMedia('(prefers-reduced-motion: reduce)');
  const view = {
    items: new Map(), // display id -> a task, a sandbox, or a closed group
    dedges: new Map(), // display id -> an edge between two items
    frames: new Map(), // group id -> the frame of an open group
    owner: new Map(), // task or sandbox id -> the display id that shows it
    contOf: new Map(), // display id or 'f:'+group id -> the group it sits in, or null
    gviews: new Map(), // group id -> its closed-group item, kept across layouts
    info: new Map(), // group id -> { key, depth, leaves, sandboxes, tasks }
  };

  const graph = createState({ view, setStatus, loadLayout: (nodes) => loadLayout(nodes), pulse: (n) => pulse(n) });
  const { state, runTime } = graph;
  const shortFile = (f) => (f ? f.split('/').pop() : '');
  const where = (n) => (n.file ? `${shortFile(n.file)}:${n.line}` : '');
  const nodeLabel = (n) => (n ? n.name : '?');
  const isGroup = (n) => n && n.kind === 'group';

  // ---------------------------------------------------------------------------
  // The graph stream

  function setStatus(kind, text) {
    if ($('status')) $('status').dataset.state = kind;
    if ($('status-text')) $('status-text').textContent = text;
    services.setStatus?.(kind, text);
  }

  // ---------------------------------------------------------------------------
  // Layout (see layout.mjs), with text measured on a canvas.

  const measure = root.ownerDocument.createElement('canvas').getContext('2d');
  function textWidth(text, font) {
    measure.font = font;
    return measure.measureText(text).width;
  }
  const { layout, itemsInFrame, frameRects, edgePath } = createLayout({
    state, view, textWidth, parentOf: (gid) => parentOf(gid), isGroup, plural, where, dEdgesOf: (n) => dEdgesOf(n), derive: () => derive(), fit: () => fit(),
  });

  // ---------------------------------------------------------------------------
  // Interaction (see interaction.mjs): selection, search, groups opened and
  // closed, dragging, pan and zoom, tooltips, and saved places.

  const {
    dispose: disposeInteraction, hookItem, toggleGroup, stepTween, fit, startDrag, loadLayout, showTip, moveTip, hideTip, select, applySearch, focusNode, focusGroup, currentDrag, clickSuppressed,
  } = createInteraction({ $, persist: options.persist, onSelect, state, view, reducedMotion, isGroup, layout, itemsInFrame, frameRects, isOpen: (gid) => isOpen(gid) });

  // ---------------------------------------------------------------------------
  // The graph (see graph.mjs): what is drawn, and its drawing.

  const { tone, drawnSource, pulse, liveRate, dRate, dCounts, dBytesRate, ends, groupChain, parentOf, isOpen, derive, dEdgesOf, draw } = createGraph({
    $, el, hostOverview: !options.persist, state, view, reducedMotion, isGroup, where, fmtCount, edgePath, frameRects, itemsInFrame,
    hookItem, select, toggleGroup, showTip, moveTip, hideTip, startDrag, currentDrag, clickSuppressed,
    nodeTip: (n) => nodeTip(n), groupTip: (gid) => groupTip(gid), edgeTip: (d) => edgeTip(d), openPackets,
  });

  // ---------------------------------------------------------------------------
  // Tables (see tables.mjs): tooltips, the header's counts, the breadcrumb
  // and the side panel.

  const { nodeTip, groupTip, edgeTip, renderSide, refresh } = createTables({
    $, el, state, view, runTime, fmtDuration, fmtBytes, fmtCount, fmtRate, plural, where, nodeLabel,
    tone, drawnSource, liveRate, dRate, dCounts, dBytesRate, ends, dEdgesOf, groupChain, parentOf, isOpen,
    select, toggleGroup, applySearch, focusNode, focusGroup, openPackets, openLinks: (...args) => services.openLinks?.(...args),
  });

  // ---------------------------------------------------------------------------
  // The frame loop: the layout when it is out of date, the view's glide, the
  // graph, the packet drawer, then the header and side panel.

  let last = performance.now();
  let animation;
  let pendingSelection, syncingSelection = false;
  const stopSelection = services.selection?.subscribe((selection) => { pendingSelection = selection; });

  function frame(now) {
    const dt = Math.min(0.1, (now - last) / 1000);
    last = now;
    if (state.layoutDirty) layout();
    if (pendingSelection && state.nodes.size) {
      const selection = pendingSelection;
      pendingSelection = null;
      const host = services.hosts?.find((host) => host.name === selection.host);
      const node = selection.node || [...state.nodes.values()].find((node) => node.kind === 'sandbox' && node.name === (host?.sandbox || selection.host))?.id;
      syncingSelection = true;
      if (node) focusNode(node); else if (!selection.host) select(null);
      syncingSelection = false;
    }
    stepTween(now);
    const total = draw(dt);
    refresh(now, total);
    animation = requestAnimationFrame(frame);
  }


  function openPackets(id) {
    if (options.persist) { services.openPackets?.(id); return; }
    const edge = view.dedges.get(id);
    if (edge) services.openLinks?.('', '', edge.members);
  }
  function onSelect(selected) {
    if (!services.selection || syncingSelection) return;
    const node = state.nodes.get(selected?.id);
    const owner = state.hosts.get(node?.host) || [...state.hosts.values()].find((host) => host.group === selected?.id);
    let sandbox = owner?.sandbox || owner?.name || (node?.kind === 'sandbox' ? node.name : null);
    let parent = node;
    const seen = new Set();
    while (!sandbox && parent && !seen.has(parent.id)) {
      seen.add(parent.id);
      parent = state.nodes.get(parent.parent);
      sandbox = parent?.kind === 'sandbox' ? parent.name : parent?.sandbox?.name;
    }
    const host = services.hosts?.find((host) => host.sandbox === sandbox || host.name === sandbox)?.name || null;
    services.selection.set({ connection: null, request: null, node: node?.id || null, host, event: selected?.event || null, links: selected?.kind === 'edge' ? (view.dedges.get(selected.id)?.members || []).map(({ e }) => e.id) : [] });
    // The map made this selection: it is not applied back to the map.
    pendingSelection = null;
  }
  const keydown = listen(options.persist ? root.ownerDocument : root, 'keydown', (ev) => {
    const active = root.ownerDocument.activeElement;
    if (ev.key === '/' && active !== $('search') && active !== $('pfilter')) {
      ev.preventDefault();
      $('search').focus();
    }
    if (ev.key === 'Escape' && active === root.ownerDocument.body) select(null);
  });
  options.onReady?.({ getEdge: (id) => view.dedges.get(id), ends, nodeLabel, fmtCount, fit: () => { if (!state.userMoved) fit(); } });
  const stop = services.connect({ ...graph, setStatus });
  renderSide();
  animation = requestAnimationFrame(frame);
  return () => {
    stopSelection?.();
    cancelAnimationFrame(animation);
    stop();
    keydown();
    disposeInteraction();
    for (const id of ['frames', 'nodes', 'edges', 'dots', 'labels', 'side', 'crumbs']) $(id).replaceChildren();
    for (const collection of [state.nodes, state.edges, state.groups, state.hosts, ...Object.values(view)]) collection.clear();
  };
}

function structure(root, el) {
  const tools = el('div', { class: 'panel-tools' }, root);
  el('input', { id: 'search', class: 'text-field', type: 'search', placeholder: 'Find a task, host or route', 'aria-label': 'Find a task, host or route', autocomplete: 'off' }, tools);
  // The CLI dashboard's icons for these two buttons.
  const icon = (id, label, path) => {
    const button = el('button', { id, class: 'icon-button', type: 'button', 'aria-label': label, title: label }, tools);
    const svg = el('svg:svg', { viewBox: '0 0 16 16', 'aria-hidden': 'true' }, button);
    el('svg:path', { d: path, fill: 'none', stroke: 'currentColor', 'stroke-width': '1.5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, svg);
  };
  icon('fit', 'Fit the map to the panel', 'M2 6V2h4M10 2h4v4M14 10v4h-4M6 14H2v-4');
  icon('reset', 'Lay the map out again', 'M3.5 8a4.5 4.5 0 1 0 1.4-3.3M3.2 2.4v2.6h2.6');
  const stats = el('div', { hidden: '' }, root);
  for (const id of ['stat-sandboxes', 'stat-tasks', 'stat-links', 'stat-rate']) el('span', { id }, stats);
  const main = el('div', { class: 'main' }, root);
  const stage = el('div', { id: 'stage', class: 'stage' }, main);
  const svg = el('svg:svg', { id: 'graph', class: 'graph', 'aria-label': 'Hosts, tasks and links' }, stage);
  const viewport = el('svg:g', { id: 'viewport' }, svg);
  for (const id of ['frames', 'edges', 'dots', 'labels', 'nodes']) el('svg:g', { id }, viewport);
  const empty = el('div', { id: 'empty', class: 'empty' }, stage);
  el('h2', { id: 'empty-title', text: 'Waiting for the world' }, empty);
  el('p', { id: 'empty-text', text: 'The map appears when the demo starts.' }, empty);
  el('nav', { id: 'crumbs', class: 'crumbs', hidden: '', 'aria-label': 'Selected groups' }, stage);
  el('aside', { id: 'side', class: 'side', 'aria-label': 'Details' }, main);
  el('div', { id: 'tip', class: 'tip', hidden: '' }, root);
}
