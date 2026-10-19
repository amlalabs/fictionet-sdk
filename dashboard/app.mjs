// The Fictionet dashboard: draws a running world from the observe API.
// `fictionet dashboard` serves this page and turns each `GET api/<op>?...`
// into one observe request (see `fictionet_observe`): `watch` for the
// graph and its changes, `packets` for the packets of one link or several,
// `packet` for one packet's layers, `pcap` for a capture. No libraries: the
// graph is SVG, laid out in columns by distance from the sandboxes, with
// each open group laid out inside its own frame.
'use strict';

import { $, el } from './dom.mjs';
import { createGraph } from './graph.mjs';
import { createInteraction } from './interaction.mjs';
import { createLayout } from './layout.mjs';
import { createPackets } from './packets.mjs';
import { createState } from './state.mjs';
import { createTables } from './tables.mjs';
import { createTransport } from './transport.mjs';

const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');

// ---------------------------------------------------------------------------
// State

// The drawing, derived from the state by `derive`: what is shown, and the
// edges between what is shown.
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
let packetView;
const { connect, packetStream, packet, download, logout, close } = createTransport({ ...graph, setStatus, onLogout: () => packetView?.close() });
$('logout').addEventListener('click', () => { logout(); location.reload(); });
addEventListener('pagehide', close);
addEventListener('pageshow', (event) => { if (event.persisted) location.reload(); });

function fmtDuration(s) {
  s = Math.max(0, Math.floor(s));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}
function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < u.length - 1);
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}
function fmtCount(n) {
  if (n < 1000) return String(Math.round(n));
  if (n < 1e6) return `${(n / 1e3).toFixed(n < 1e4 ? 1 : 0)}k`;
  return `${(n / 1e6).toFixed(1)}M`;
}
function fmtRate(n) {
  if (n <= 0) return '0';
  if (n < 10) return n.toFixed(1);
  return fmtCount(n);
}
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const shortFile = (f) => (f ? f.split('/').pop() : '');
const where = (n) => (n.file ? `${shortFile(n.file)}:${n.line}` : '');
const nodeLabel = (n) => (n ? n.name : '?');
const isGroup = (n) => n && n.kind === 'group';

// ---------------------------------------------------------------------------
// The graph stream

function setStatus(kind, text) {
  $('status').dataset.state = kind;
  $('status-text').textContent = text;
}

// ---------------------------------------------------------------------------
// Layout (see layout.mjs), with text measured on a canvas.

const measure = document.createElement('canvas').getContext('2d');
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
  hookItem, toggleGroup, stepTween, fit, startDrag, loadLayout, showTip, moveTip, hideTip, select, applySearch, focusNode, focusGroup, currentDrag, clickSuppressed,
} = createInteraction({ state, view, reducedMotion, isGroup, layout, itemsInFrame, frameRects, isOpen: (gid) => isOpen(gid) });

// ---------------------------------------------------------------------------
// The graph (see graph.mjs): what is drawn, and its drawing.

const { tone, drawnSource, pulse, liveRate, dRate, dCounts, dBytesRate, ends, groupChain, parentOf, isOpen, derive, dEdgesOf, draw } = createGraph({
  state, view, reducedMotion, isGroup, where, fmtCount, edgePath, frameRects, itemsInFrame,
  hookItem, select, toggleGroup, showTip, moveTip, hideTip, startDrag, currentDrag, clickSuppressed,
  nodeTip: (n) => nodeTip(n), groupTip: (gid) => groupTip(gid), edgeTip: (d) => edgeTip(d), openPackets: (id) => openPackets(id),
});

// ---------------------------------------------------------------------------
// Tables (see tables.mjs): tooltips, the header's counts, the breadcrumb
// and the side panel.

const { nodeTip, groupTip, edgeTip, renderSide, refresh } = createTables({
  state, view, runTime, fmtDuration, fmtBytes, fmtCount, fmtRate, plural, where, nodeLabel,
  tone, drawnSource, liveRate, dRate, dCounts, dBytesRate, ends, dEdgesOf, groupChain, parentOf, isOpen,
  select, toggleGroup, applySearch, focusNode, focusGroup, openPackets: (id) => openPackets(id), openLinks: (...args) => openLinks(...args),
});

packetView = createPackets({
  $, el, packetStream, packet, download, getEdge: (id) => view.dedges.get(id), ends, nodeLabel, fmtCount,
  fit: () => { if (!state.userMoved) fit(); },
});
const { open: openPackets, openLinks, flush: flushPackets } = packetView;

// ---------------------------------------------------------------------------
// The frame loop: the layout when it is out of date, the view's glide, the
// graph, the packet drawer, then the header and side panel.

let last = performance.now();

function frame(now) {
  const dt = Math.min(0.1, (now - last) / 1000);
  last = now;
  if (state.layoutDirty) layout();
  stepTween(now);
  const total = draw(dt);
  flushPackets();
  refresh(now, total);
  requestAnimationFrame(frame);
}

// ---------------------------------------------------------------------------
// Theme: the system's, until the viewer picks one.

function storedTheme() {
  try {
    return localStorage.getItem('fictionet-theme');
  } catch {
    return null;
  }
}
function applyTheme(t) {
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
applyTheme(new URLSearchParams(location.search).get('theme') || storedTheme());
$('theme').addEventListener('click', () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  const next = dark ? 'light' : 'dark';
  applyTheme(next);
  try {
    localStorage.setItem('fictionet-theme', next);
  } catch {
    // Private windows may refuse storage; the choice lasts for this page.
  }
});

document.addEventListener('keydown', (ev) => {
  if (ev.key === '/' && document.activeElement !== $('search') && document.activeElement !== $('pfilter')) {
    ev.preventDefault();
    $('search').focus();
  }
  if (ev.key === 'Escape' && document.activeElement === document.body) select(null);
});

connect();
renderSide();
requestAnimationFrame(frame);
