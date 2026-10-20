// Interaction with the Fictionet dashboard's graph: selection and search,
// opening and closing groups, dragging, pan and zoom, tooltips, and the
// places and open groups the viewer keeps per world. components/map.mjs passes in the
// state and view and the layout's steps, and moves the view's glide on
// once a frame with `stepTween`.

import { listen } from './dom.mjs';
import { HEAD } from './layout.mjs';

export function createInteraction({ $, onSelect = () => {}, persist = false, state, view, reducedMotion, isGroup, layout, itemsInFrame, frameRects, isOpen }) {
  const cleanup = [];
  let clickTimer;
  const on = (...args) => cleanup.push(listen(...args));

  /// Click, keyboard, tooltip and drag for a drawn item.
  function hookItem(g, n, onSelect, tipFill) {
    g.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (!suppressClick) onSelect();
    });
    g.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') {
        ev.preventDefault();
        onSelect();
      }
      if (isGroup(n) && (ev.key === '+' || ev.key === '=')) toggleGroup(n.gid);
    });
    g.addEventListener('pointerenter', (ev) => showTip(ev, tipFill));
    g.addEventListener('pointermove', moveTip);
    g.addEventListener('pointerleave', hideTip);
    g.addEventListener('pointerdown', (ev) => startDrag(ev, [n], n));
  }

  // ---------------------------------------------------------------------------
  // Opening and closing groups

  /// Opens a closed group, or closes an open one, where it is: the view moves
  /// so the group's top left corner stays on the same spot of the screen.
  function toggleGroup(gid) {
    const info = view.info.get(gid);
    if (!info) return;
    const open = isOpen(gid);
    // Where it is now, on screen.
    let anchor = null;
    if (open) {
      const f = view.frames.get(gid);
      if (f?.box) anchor = { x: f.box.x, y: f.box.y + HEAD };
    } else {
      const gv = view.items.get(gid);
      if (gv) anchor = { x: gv.x, y: gv.y };
    }
    const k0 = state.view.k;
    const screen = anchor && { x: anchor.x * k0 + state.view.x, y: anchor.y * k0 + state.view.y };
    state.expanded.set(info.key, !open);
    saveLayout();
    // The view stays as it is: no fitting while the group changes.
    state.userMoved = true;
    layout();
    if (!open && anchor) {
      // What the group holds grows out of where the group was.
      for (const n of itemsInFrame(gid)) {
        if (!n.g) {
          n.x = anchor.x;
          n.y = anchor.y;
        }
      }
    }
    let target = null;
    if (open) {
      const gv = view.items.get(gid);
      if (gv) {
        target = { x: gv.tx, y: gv.ty };
        if (anchor) {
          gv.x = anchor.x;
          gv.y = anchor.y;
        }
      }
    } else {
      frameRects(true);
      const f = view.frames.get(gid);
      if (f?.box) target = { x: f.box.x, y: f.box.y + HEAD };
    }
    if (anchor && target) {
      const k = state.view.k;
      state.view.x = screen.x - target.x * k;
      state.view.y = screen.y - target.y * k;
      // Every drawn item glides; the view jumps so the group stays put.
      for (const n of view.items.values()) {
        if (Number.isNaN(n.x)) continue;
        n.x += target.x - anchor.x;
        n.y += target.y - anchor.y;
      }
      state.userMoved = true;
      applyView();
    }
    // Then, if the group now reaches past the view, the view moves (and
    // zooms out, if it must) until it shows the whole group.
    frameRects(true);
    const f = view.frames.get(gid);
    const item = view.items.get(gid);
    const box = f?.box || (item && { x: item.tx, y: item.ty, w: item.w, h: item.h });
    if (box) showBox(box);
    select({ kind: 'group', id: gid });
  }

  /// Moves the view smoothly so that `box` is on screen, zooming out only
  /// if it is bigger than the view.
  function showBox(box) {
    const r = stage.getBoundingClientRect();
    const m = 28;
    const v = { ...state.view };
    const k = Math.min(v.k, (r.width - m * 2) / box.w, (r.height - m * 2) / box.h);
    // Zoom about the box's top left corner.
    v.x += box.x * (v.k - k);
    v.y += box.y * (v.k - k);
    v.k = k;
    const left = box.x * k + v.x;
    const top = box.y * k + v.y;
    const right = left + box.w * k;
    const bottom = top + box.h * k;
    if (right > r.width - m) v.x -= right - (r.width - m);
    if (bottom > r.height - m) v.y -= bottom - (r.height - m);
    if (left + (v.x - state.view.x) < m) v.x += m - (box.x * k + v.x);
    if (top + (v.y - state.view.y) < m) v.y += m - (box.y * k + v.y);
    if (Math.abs(v.x - state.view.x) < 1 && Math.abs(v.y - state.view.y) < 1 && v.k === state.view.k) return;
    tweenView(v);
  }

  let viewTween = null;
  function tweenView(to) {
    if (reducedMotion.matches) {
      state.view = to;
      applyView();
      return;
    }
    viewTween = { from: { ...state.view }, to, t0: performance.now(), dur: 450 };
  }

  function stepTween(now) {
    if (!viewTween) return;
    const { from, to, t0, dur } = viewTween;
    const t = Math.min(1, (now - t0) / dur);
    const e = 1 - Math.pow(1 - t, 3);
    state.view = { x: from.x + (to.x - from.x) * e, y: from.y + (to.y - from.y) * e, k: from.k + (to.k - from.k) * e };
    applyView();
    if (t >= 1) viewTween = null;
  }

  // ---------------------------------------------------------------------------
  // Dragging, pan and zoom

  const stage = $('stage');
  const graphSvg = $('graph');
  const viewport = $('viewport');

  function applyView() {
    const { x, y, k } = state.view;
    viewport.setAttribute('transform', `translate(${x.toFixed(1)},${y.toFixed(1)}) scale(${k.toFixed(4)})`);
  }

  function fit() {
    const nodes = [...view.items.values()];
    if (!nodes.length) return;
    let minX = Math.min(...nodes.map((n) => n.tx));
    let minY = Math.min(...nodes.map((n) => n.ty)) - 12;
    let maxX = Math.max(...nodes.map((n) => n.tx + n.w)) + 60;
    let maxY = Math.max(...nodes.map((n) => n.ty + n.h));
    for (const f of frameRects(true)) {
      if (!f.box) continue;
      minX = Math.min(minX, f.box.x);
      minY = Math.min(minY, f.box.y);
      maxX = Math.max(maxX, f.box.x + f.box.w);
      maxY = Math.max(maxY, f.box.y + f.box.h);
    }
    const r = stage.getBoundingClientRect();
    const pad = 56;
    const k = Math.min(1.35, (r.width - pad * 2) / (maxX - minX), (r.height - pad * 2 - 30) / (maxY - minY));
    state.view = {
      k,
      x: (r.width - (maxX - minX) * k) / 2 - minX * k,
      y: (r.height - 30 - (maxY - minY) * k) / 2 - minY * k,
    };
    applyView();
  }

  on(stage,
    'wheel',
    (ev) => {
      ev.preventDefault();
      viewTween = null;
      const r = stage.getBoundingClientRect();
      const px = ev.clientX - r.left;
      const py = ev.clientY - r.top;
      const k = Math.min(4, Math.max(0.15, state.view.k * Math.exp(-ev.deltaY * 0.0015)));
      const f = k / state.view.k;
      state.view = { k, x: px - (px - state.view.x) * f, y: py - (py - state.view.y) * f };
      state.userMoved = true;
      applyView();
    },
    { passive: false },
  );

  // A drag of items: { items, start: [{x, y}], px, py, moved, pointer }.
  let drag = null;
  // Set after a drag, so the click that ends it does not select.
  let suppressClick = false;

  function startDrag(ev, items, _n) {
    if (ev.button !== 0 || ev.target.closest('.toggle')) return;
    ev.stopPropagation();
    drag = { items, start: items.map((n) => ({ x: n.x, y: n.y })), px: ev.clientX, py: ev.clientY, moved: false, pointer: ev.pointerId };
    suppressClick = false;
    // The pointer is captured only once the drag moves, so that a click or
    // double-click without a move still reaches the item.
  }

  let pan = null;
  on(stage, 'pointerdown', (ev) => {
    if (drag || ev.target.closest('.node, .edge .hit, .fhead, button, .crumbs')) return;
    viewTween = null;
    pan = { x: ev.clientX, y: ev.clientY, vx: state.view.x, vy: state.view.y, moved: false };
    stage.setPointerCapture(ev.pointerId);
  });
  on(stage, 'pointermove', (ev) => {
    if (drag) {
      const dx = (ev.clientX - drag.px) / state.view.k;
      const dy = (ev.clientY - drag.py) / state.view.k;
      if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 4 / state.view.k) return;
      if (!drag.moved) {
        drag.moved = true;
        stage.setPointerCapture(drag.pointer);
        hideTip();
        stage.classList.add('dragging');
      }
      drag.items.forEach((n, i) => {
        n.x = n.tx = drag.start[i].x + dx;
        n.y = n.ty = drag.start[i].y + dy;
      });
      return;
    }
    if (!pan) return;
    const dx = ev.clientX - pan.x;
    const dy = ev.clientY - pan.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) {
      pan.moved = true;
      stage.classList.add('panning');
    }
    state.view.x = pan.vx + dx;
    state.view.y = pan.vy + dy;
    if (pan.moved) state.userMoved = true;
    applyView();
  });
  on(stage, 'pointerup', () => {
    if (drag) {
      if (drag.moved) {
        // The dragged items stay where they were dropped.
        for (const n of drag.items) {
          state.pins.set(n.key, { x: Math.round(n.x), y: Math.round(n.y) });
          n.pinned = true;
        }
        suppressClick = true;
        clearTimeout(clickTimer);
        clickTimer = setTimeout(() => (suppressClick = false), 0);
        state.userMoved = true;
        saveLayout();
      }
      drag = null;
      stage.classList.remove('dragging');
      return;
    }
    if (pan && !pan.moved) select(null);
    pan = null;
    stage.classList.remove('panning');
  });
  on(stage, 'dblclick', (ev) => {
    if (ev.target.closest('.node, .edge .hit, .fhead, button, .crumbs, .legend')) return;
    resetLayout();
  });
  on($('fit'), 'click', () => {
    state.userMoved = false;
    fit();
  });
  on($('reset'), 'click', resetLayout);

  /// Forgets every dragged place, lays the graph out again, and fits it.
  function resetLayout() {
    state.pins.clear();
    saveLayout();
    state.userMoved = false;
    layout();
    fit();
  }

  const resize = new ResizeObserver(() => {
    if (!state.userMoved) fit();
  });
  resize.observe(stage);

  // The viewer's places and open groups, kept per world in this browser.
  // A world is known by its own source files, which stay the same from run
  // to run.
  function loadLayout(nodes) {
    const files = [...new Set(nodes.filter((n) => n.file && !n.file.startsWith('src/')).map((n) => n.file))].sort();
    state.worldKey = `fictionet-layout:${files.join(',') || 'world'}`;
    state.pins.clear();
    state.expanded.clear();
    if (!persist) return;
    try {
      const saved = JSON.parse(localStorage.getItem(state.worldKey) || 'null');
      if (saved) {
        for (const [k, v] of Object.entries(saved.pins || {})) state.pins.set(k, v);
        for (const [k, v] of Object.entries(saved.open || {})) state.expanded.set(k, v);
      }
    } catch {
      // Storage may be refused or hold something else; start afresh.
    }
  }

  function saveLayout() {
    if (!persist || !state.worldKey) return;
    try {
      localStorage.setItem(state.worldKey, JSON.stringify({ pins: Object.fromEntries(state.pins), open: Object.fromEntries(state.expanded) }));
    } catch {
      // Private windows may refuse storage; the layout lasts for this page.
    }
  }

  // ---------------------------------------------------------------------------
  // Tooltips

  const tip = $('tip');
  let tipFill = null;

  function showTip(ev, fill) {
    if (drag?.moved) return;
    tipFill = fill;
    tip.replaceChildren(...fill());
    tip.hidden = false;
    moveTip(ev);
  }
  function moveTip(ev) {
    if (tip.hidden) return;
    if (tipFill) tip.replaceChildren(...tipFill());
    const r = tip.getBoundingClientRect();
    let x = ev.clientX + 16;
    let y = ev.clientY + 14;
    if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - 16;
    if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - 14;
    tip.style.left = `${x}px`;
    tip.style.top = `${y}px`;
  }
  function hideTip() {
    tip.hidden = true;
    tipFill = null;
  }

  // ---------------------------------------------------------------------------
  // Selection and search

  function select(sel) {
    state.selected = sel;
    onSelect(sel);
    for (const n of view.items.values()) {
      const on = !!sel && ((sel.kind === 'node' && sel.id === n.id) || (sel.kind === 'group' && isGroup(n) && sel.id === n.gid));
      n.g?.classList.toggle('selected', on);
    }
    for (const d of view.dedges.values()) d.g?.classList.toggle('selected', !!sel && sel.kind === 'edge' && sel.id === d.id);
    state.sideDirty = true;
  }

  on($('search'), 'input', (ev) => {
    state.search = ev.target.value.trim().toLowerCase();
    applySearch();
  });
  on($('search'), 'keydown', (ev) => {
    if (ev.key === 'Enter') {
      const hit = [...view.items.values()].find((n) => matches(n));
      if (hit) {
        const r = stage.getBoundingClientRect();
        state.view.x = r.width / 2 - (hit.tx + hit.w / 2) * state.view.k;
        state.view.y = r.height / 2 - (hit.ty + hit.h / 2) * state.view.k;
        state.userMoved = true;
        applyView();
        select(isGroup(hit) ? { kind: 'group', id: hit.gid } : { kind: 'node', id: hit.id });
      }
    } else if (ev.key === 'Escape') {
      ev.target.value = '';
      state.search = '';
      applySearch();
    }
  });

  function leafMatches(n) {
    const q = state.search;
    if (`${n.name} ${n.file || ''}:${n.line || ''} ${n.kind}`.toLowerCase().includes(q)) return true;
    for (const id of n.edges) {
      const e = state.edges.get(id);
      if (e?.label && e.label.toLowerCase().includes(q)) return true;
    }
    return false;
  }

  /// Whether a drawn item matches the search. A closed group matches by its
  /// name, or when anything inside it matches.
  function matches(n) {
    const q = state.search;
    if (!q) return false;
    if (!isGroup(n)) return leafMatches(n);
    if (n.name.toLowerCase().includes(q)) return true;
    for (const [id, did] of view.owner) {
      if (did === n.id && leafMatches(state.nodes.get(id))) return true;
    }
    return false;
  }

  function applySearch() {
    const q = state.search;
    for (const n of view.items.values()) {
      if (!n.g) continue;
      const m = q && matches(n);
      n.g.classList.toggle('match', !!m);
      n.g.classList.toggle('dim', !!q && !m);
    }
    for (const d of view.dedges.values()) {
      if (!d.g) continue;
      const a = view.items.get(d.a);
      const b = view.items.get(d.b);
      const m = q && ((d.label || '').toLowerCase().includes(q) || (a && matches(a)) || (b && matches(b)));
      d.g.classList.toggle('dim', !!q && !m);
    }
    state.sideDirty = true;
  }

  /// Brings drawn item `n` into the middle of the view.
  function centerOn(n) {
    const r = stage.getBoundingClientRect();
    state.view.x = r.width / 2 - (n.tx + n.w / 2) * state.view.k;
    state.view.y = r.height / 2 - (n.ty + n.h / 2) * state.view.k;
    state.userMoved = true;
    applyView();
  }

  /// Selects a task or sandbox and brings it into view, or the closed group
  /// it is drawn in.
  function focusNode(id) {
    const n = state.nodes.get(id);
    if (!n) return;
    select({ kind: 'node', id });
    const shown = view.items.get(view.owner.get(id));
    if (shown) centerOn(shown);
  }

  /// Selects a group and brings it into view.
  function focusGroup(gid) {
    select({ kind: 'group', id: gid });
    const item = view.items.get(gid);
    if (item) return centerOn(item);
    const f = view.frames.get(gid);
    if (f?.box) centerOn({ tx: f.box.x, ty: f.box.y, w: f.box.w, h: f.box.h });
  }

  return {
    dispose() {
      cleanup.splice(0).forEach((remove) => remove());
      resize.disconnect();
      clearTimeout(clickTimer);
      hideTip();
      drag = pan = viewTween = null;
    },
    hookItem, toggleGroup, stepTween, fit, startDrag, loadLayout, showTip, moveTip, hideTip, select, applySearch, focusNode, focusGroup,
    // The drag in progress, if any, and whether the click that ends one is being ignored.
    currentDrag: () => drag,
    clickSuppressed: () => suppressClick,
  };
}
