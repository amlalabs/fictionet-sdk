// The control room panel for the Fictionet page kit.
//
// mount(root, services, options) builds the panel synchronously and returns a
// dispose function. The page kit owns the one state stream, so the panel
// subscribes through services.state and never opens its own. Commands go
// through services.transport to the control port named in the options.
//
// Three.js loads only inside mount. The 3D modules are imported dynamically, so
// a failed download shows in the panel with the library name and the command
// that fixes it. The knobs and the text readings do not need Three.js.

import { instruments, formatValue, tagKey } from './instruments.mjs';
import { DEFAULT_VIEW, STANDING_SPOTS } from './board-layout.mjs';
import {
  advanceButton,
  advanceSwitch,
  coastDial,
  createButton,
  createDial,
  createRotary,
  createSwitch,
  dialValue,
  fault,
  faultCommand,
  hotLegCount,
  pressButton,
  plant,
  postCommand,
  releaseButton,
  releaseDial,
  releaseRotary,
  resolveDetent,
  rotaryValue,
  setDial,
  settleDial,
  switchAtRest,
  throwSwitch,
  toggleSwitch,
  turnDial,
  turnRotary,
} from './knobs.mjs';

const TURBINE_VALVE_VALUES = Object.freeze([0, 250, 500, 750, 1000]);
export const PALETTE_TOKENS = Object.freeze({
  lightKey: '--light-key',
  lightGround: '--light-ground',
  plantKey: '--plant-key',
  rubber: '--rubber',
  lampGlow: '--lamp-glow',
  lampOff: '--lamp-off',
  lampInk: '--lamp-ink',
  lampLegend: '--lamp-legend',
  surface: '--surface',
  raised: '--surface-raised',
  sunken: '--surface-sunken',
  line: '--line',
  ink: '--ink',
  text: '--text',
  steel: '--steel',
  metal: '--metal',
  accent: '--accent',
  warning: '--warning',
  strongLine: '--line-strong',
  steam: '--steam',
  coldCoolant: '--coolant-cold',
  hotCoolant: '--coolant-hot',
});
export function paletteReady(values) {
  return Object.keys(PALETTE_TOKENS).every((name) =>
    typeof values[name] === 'string' && values[name].trim().length > 0);
}

const LOAD_FAILURE = 'Run `cargo xtask demo libraries`, then rebuild.';

/** Knobs in the order they appear on the page and the console. */
const KNOBS = Object.freeze([
  // Plant controls. These post the plant's Command.
  {
    id: 'rod-demand',
    group: 'plant',
    kind: 'dial',
    label: 'Rod demand',
    channel: 'plant',
    min: 0,
    max: 1000,
    step: 1,
    setting: (value) => Math.round(value.truth.reactor.rod_demand_percent * 10),
    command: (tenths) => plant.rodDemand(tenths),
    readout: (value, knob) =>
      `Demand ${formatValue(dialValue(knob.model) / 10, '%')} · Rods ${formatValue(value.truth.reactor.control_rod_percent, '%')}`,
    describe: (percent) => `${formatValue(percent / 10, '%')} demanded`,
  },
  {
    id: 'turbine-valve',
    group: 'plant',
    kind: 'rotary',
    label: 'Turbine valve',
    channel: 'plant',
    values: TURBINE_VALVE_VALUES,
    setting: (value) => nearestIndex(TURBINE_VALVE_VALUES, Math.round(value.truth.secondary.turbine_valve_percent * 10)),
    command: (permille) => plant.valveDemand('turbine', permille),
    readout: (value) => `Valve ${formatValue(value.truth.secondary.turbine_valve_percent, '%')}`,
    describe: (permille) => `${formatValue(permille / 10, '%')} demanded`,
  },
  pumpSwitch('coolant-pump-a', 'Coolant pump A', 'a'),
  pumpSwitch('coolant-pump-b', 'Coolant pump B', 'b'),
  controllerSwitch('feed-level-a', 'Feed level A control', { feed_level: 'a' }, (v) => v.truth.controllers.feed_level[0]),
  controllerSwitch('feed-level-b', 'Feed level B control', { feed_level: 'b' }, (v) => v.truth.controllers.feed_level[1]),
  controllerSwitch('pressurizer-control', 'Pressurizer pressure control', 'pressurizer_pressure', (v) => v.truth.controllers.pressurizer_pressure),
  controllerSwitch('steam-dump-control', 'Steam dump control', 'steam_dump', (v) => v.truth.controllers.steam_dump),
  {
    id: 'heaters',
    group: 'plant',
    kind: 'switch',
    label: 'Pressurizer heaters',
    channel: 'plant',
    setting: (value) => value.truth.primary.heaters_on,
    command: (on) => plant.heaters(on),
    readout: (value, knob) => (knob.model.on ? 'On' : 'Off'),
  },
  {
    id: 'manual-trip',
    group: 'plant',
    kind: 'button',
    label: 'Manual trip',
    channel: 'plant',
    command: () => plant.manualTrip(),
  },
  {
    id: 'reset-trip',
    group: 'plant',
    kind: 'button',
    label: 'Reset trip',
    channel: 'plant',
    command: () => plant.resetTrip(),
  },
  {
    id: 'acknowledge',
    group: 'plant',
    kind: 'button',
    label: 'Acknowledge alarms',
    channel: 'plant',
    command: () => plant.acknowledgeAlarms(),
  },
  // Fault injection. These post a FaultCommand carrying the snapshot's revision.
  faultSwitch('telemetry-quiet', 'Telemetry quiet', (value) => value.faults.telemetry_quiet, (on) => fault.telemetryQuiet(on)),
  faultSwitch(
    'condenser-loss',
    'Condenser cooling loss',
    (value) => hasProcess(value, 'condenser_cooling_loss'),
    (on) => fault.condenserCoolingLoss(on),
  ),
  faultSwitch(
    'coolant-trip-b',
    'Coolant pump B trip',
    (value) => hasProcess(value, 'coolant_pump_trip:b'),
    (on) => fault.coolantPumpTrip('b', on),
  ),
  {
    id: 'hot-leg-b-stuck',
    group: 'faults',
    kind: 'switch',
    label: 'Hot leg B sensor stuck',
    channel: 'faults',
    setting: (value, view) => view.pairs.find((p) => p.key === 'hot_leg:b')?.fault === 'stuck',
    command: (on, view) => {
      const pair = view.pairs.find((p) => p.key === 'hot_leg:b');
      const reading = pair?.reported ?? pair?.trueValue;
      return fault.stuckHotLeg('b', on ? hotLegCount(reading) : 0, on);
    },
    readout: (value, knob) => (knob.model.on ? 'Stuck at the current reading' : 'Reads the plant'),
  },
  {
    id: 'clear-faults',
    group: 'faults',
    kind: 'button',
    label: 'Clear all faults',
    channel: 'faults',
    command: () => fault.clearAll(),
  },
]);

function pumpSwitch(id, label, loop) {
  return {
    id,
    group: 'plant',
    kind: 'switch',
    label,
    channel: 'plant',
    setting: (value) => value.truth.primary.loops[loop === 'a' ? 0 : 1].pump_running,
    command: (on) => plant.pump({ coolant: loop }, on),
    readout: (value, knob) => (knob.model.on ? 'Running' : 'Stopped'),
  };
}

function controllerSwitch(id, label, controller, modeOf) {
  return {
    id,
    group: 'plant',
    kind: 'switch',
    label,
    channel: 'plant',
    setting: (value) => modeOf(value) === 'manual',
    command: (manual) => plant.controller(controller, manual ? 'manual' : 'automatic'),
    readout: (value, knob) => (knob.model.on ? 'Manual' : 'Automatic'),
  };
}

function faultSwitch(id, label, present, change) {
  return {
    id,
    group: 'faults',
    kind: 'switch',
    label,
    channel: 'faults',
    setting: present,
    command: (on) => change(on),
    readout: (value, knob) => (knob.model.on ? 'Fault injected' : 'No fault'),
  };
}

function hasProcess(value, tag) {
  return value.faults.process.some((fault) => fault !== null && tagKey(fault) === tag);
}

function nearestIndex(values, target) {
  let index = 0;
  for (let i = 1; i < values.length; i++) {
    if (Math.abs(values[i] - target) < Math.abs(values[index] - target)) index = i;
  }
  return index;
}

/** A plant time in minutes, seconds and tenths: 2:00.0. */
export function formatClock(ms) {
  if (ms === null || ms === undefined) return 'no time';
  const total = ms / 1000;
  const minutes = Math.floor(total / 60);
  const seconds = total - minutes * 60;
  return `${minutes}:${seconds.toFixed(1).padStart(4, '0')}`;
}

/** Creates an element with attributes, text and children, all set once. */
function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'text') node.textContent = value;
    else if (key === 'class') node.className = value;
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  node.append(...children.filter((child) => child !== null && child !== undefined));
  return node;
}

export function mount(root, services, options = {}) {
  const controller = new AbortController();
  const listeners = [];
  const listen = (target, type, handler, opts) => {
    target.addEventListener(type, handler, opts);
    listeners.push(() => target.removeEventListener(type, handler, opts));
  };
  const reduceQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const reducedMotion = () => reduceQuery.matches;
  const darkQuery = window.matchMedia('(prefers-color-scheme: dark)');
  const forcedQuery = window.matchMedia('(forced-colors: active)');

  let disposed = false;
  let unsubscribe = null;
  let latest = null; // { revision, value, view }
  let board = null;
  let readings = null;
  let tickRaf = 0;
  let lastTick = 0;
  let viewName = DEFAULT_VIEW;
  const knobs = new Map();
  const knobList = [];

  const palette = () => readPalette(root);

  // ---- DOM ----------------------------------------------------------------

  root.classList.add('cr-root');
  const status = h('p', { class: 'cr-headline', text: 'Waiting for the first plant snapshot.' });
  const facts = h('dl', { class: 'cr-facts' });
  const factValues = {};
  for (const [key, label] of [
    ['time', 'Plant time'],
    ['telemetry', 'Telemetry'],
    ['revision', 'Revision'],
    ['actions', 'Operator actions'],
  ]) {
    factValues[key] = h('dd', { text: '—' });
    facts.append(h('div', { class: 'cr-fact' }, h('dt', { text: label }), factValues[key]));
  }

  const alarmList = h('ul', { class: 'cr-alarm-list' }, h('li', { text: 'Waiting for the plant.' }));
  const processList = h('ul', { class: 'cr-process-list' }, h('li', { text: 'Waiting for the plant.' }));
  const overlayStatus = h('p', { class: 'cr-scene-status', role: 'status', 'aria-live': 'off', text: 'Waiting for the first plant snapshot.' });
  const vantageButtons = [
    ...Object.entries(STANDING_SPOTS).map(([name, spot]) => [name, spot.name]),
    ['reactor', 'Reactor building'], ['turbine', 'Turbine hall'],
  ].map(([name, label]) => h('button', { type: 'button', class: 'cr-vantage', 'data-view': name, 'aria-pressed': name === viewName ? 'true' : 'false', text: label }));
  const controlStage = h('div', { class: 'cr-stage' });
  const viewport = h('section', { class: 'cr-view', 'aria-label': 'Views of the plant' }, controlStage,
    h('div', { class: 'cr-vantages', role: 'group', 'aria-label': 'Vantage point' }, ...vantageButtons), overlayStatus);
  const walkHelp = h('p', { id: 'cr-walk-help', class: 'cr-note', text: 'Focus the scene to walk with WASD or arrow keys. Drag to look. Click to lock the pointer. Press Esc to release it.' });

  const knobGroups = {
    plant: h('div', { class: 'cr-knob-grid' }),
    faults: h('div', { class: 'cr-knob-grid' }),
  };
  const controls = h(
    'section',
    { class: 'cr-controls', 'aria-label': 'Knobs, switches and pushbuttons' },
    h(
      'div',
      { class: 'cr-group', role: 'group', 'aria-labelledby': 'cr-plant-title' },
      h('h2', { id: 'cr-plant-title', text: 'Plant controls' }),
      knobGroups.plant,
    ),
  );
  const instructor = h('section', { class: 'cr-group cr-group-faults', 'aria-labelledby': 'cr-faults-title' },
    h('h2', { id: 'cr-faults-title', text: 'Instructor station' }),
    h('p', { class: 'cr-note', text: "Fault levers for the evaluation. The operator's controls do not include these." }),
    processList, knobGroups.faults);
  const readingsHost = h('div', { class: 'cr-readings' });
  root.append(h('section', { class: 'cr-panel' }, viewport,
    h('section', { class: 'cr-fallback', 'aria-label': 'Plant status and text controls' }, walkHelp, status, facts,
      h('h2', { text: 'Alarms' }), alarmList, controls, readingsHost, instructor)));

  // Knobs are built once. Their DOM follows the model every tick.
  for (const spec of KNOBS) {
    const knob = buildKnob(spec);
    knobs.set(spec.id, knob);
    knobList.push(knob);
    knobGroups[spec.group].append(knob.root);
  }

  // ---- Vantage points -----------------------------------------------------

  function showView(name) {
    viewName = name;
    for (const button of vantageButtons) {
      button.setAttribute('aria-pressed', String(button.dataset.view === name));
    }
    board?.setView(name);
  }
  for (const button of vantageButtons) {
    listen(button, 'click', () => showView(button.dataset.view));
  }

  // ---- Knob models and DOM ------------------------------------------------

  function buildKnob(spec) {
    const ids = { name: `cr-knob-${spec.id}-name`, read: `cr-knob-${spec.id}-read`, status: `cr-knob-${spec.id}-status` };
    const knob = {
      spec,
      model: initialModel(spec),
      pending: false,
      seq: 0,
      dragging: false,
      trail: [],
      lastAngle: 0,
      releasedPending: false,
      root: null,
      face: null,
      readEl: null,
      statusEl: null,
    };
    const name = h('p', { class: 'cr-knob-name', id: ids.name, text: spec.label });
    knob.readEl = h('p', { class: 'cr-knob-read', id: ids.read });
    knob.statusEl = h('p', { class: 'cr-knob-status', id: ids.status, role: 'status' });

    if (spec.kind === 'dial' || spec.kind === 'rotary') {
      const pointer = h('span', { class: 'cr-pointer', 'aria-hidden': 'true' });
      knob.face = h('div', {
        class: `cr-knob-face cr-${spec.kind}`,
        role: 'slider',
        tabindex: '0',
        'aria-labelledby': ids.name,
        'aria-describedby': `${ids.read} ${ids.status}`,
        'aria-valuemin': spec.kind === 'dial' ? '0' : String(spec.values[0] / 10),
        'aria-valuemax': spec.kind === 'dial' ? '100' : String(spec.values[spec.values.length - 1] / 10),
      }, pointer);
      knob.pointer = pointer;
      knob.control = knob.face;
      knob.root = h('div', { class: 'cr-knob', 'data-kind': spec.kind, 'data-group': spec.group }, knob.face, name, knob.readEl, knob.statusEl);
      wireDial(knob);
    } else if (spec.kind === 'switch') {
      const lever = h('span', { class: 'cr-switch-lever', 'aria-hidden': 'true' });
      knob.lever = lever;
      knob.control = h('button', {
        type: 'button',
        class: 'cr-switch',
        role: 'switch',
        'aria-checked': 'false',
        'aria-labelledby': ids.name,
        'aria-describedby': `${ids.read} ${ids.status}`,
      }, h('span', { class: 'cr-switch-track', 'aria-hidden': 'true' }, lever));
      knob.root = h('div', { class: 'cr-knob', 'data-kind': 'switch', 'data-group': spec.group }, knob.control, name, knob.readEl, knob.statusEl);
      listen(knob.control, 'click', () => onSwitch(knob));
    } else {
      knob.cap = h('span', { class: 'cr-push-cap', 'aria-hidden': 'true' });
      knob.control = h('button', {
        type: 'button',
        class: 'cr-push',
        'aria-labelledby': ids.name,
        'aria-describedby': ids.status,
      }, knob.cap);
      knob.root = h('div', { class: 'cr-knob', 'data-kind': 'button', 'data-group': spec.group }, knob.control, name, knob.statusEl);
      wireButton(knob);
    }
    return knob;
  }

  function initialModel(spec) {
    if (spec.kind === 'dial') return createDial({ min: spec.min, max: spec.max, step: spec.step });
    if (spec.kind === 'rotary') return createRotary(spec.values, 0);
    if (spec.kind === 'switch') return createSwitch(false);
    return createButton();
  }

  /** The knob's DOM from its model. Motion only moves pixels; numbers come from the snapshot. */
  function paintKnob(knob) {
    const { spec, model } = knob;
    if (spec.kind === 'dial' || spec.kind === 'rotary') {
      const fraction = model.angle / model.sweep;
      knob.pointer.style.transform = `rotate(${-135 + 270 * fraction}deg)`;
      const percent = spec.kind === 'dial' ? dialValue(model) : rotaryValue(model);
      knob.face.setAttribute('aria-valuenow', String(percent / 10));
      knob.face.setAttribute('aria-valuetext', spec.describe(percent));
    } else if (spec.kind === 'switch') {
      knob.lever.style.transform = `translateY(${(1 - model.travel) * 46}px)`;
      knob.control.setAttribute('aria-checked', String(model.on));
    } else {
      knob.cap.style.transform = `translateY(${model.depth * 3}px)`;
    }
    // aria-disabled, not disabled: a disabled control would drop keyboard focus.
    const blocked = disabledFor(knob) || (knob.pending && spec.kind !== 'dial' && spec.kind !== 'rotary');
    knob.control.setAttribute('aria-disabled', String(blocked));
    knob.root.dataset.pending = String(knob.pending);
  }

  function disabledFor(knob) {
    if (knob.spec.channel === 'plant') return !options.command;
    return !options.faults || latest === null;
  }

  function paintReadout(knob) {
    if (!latest) {
      knob.readEl.textContent = 'Waiting for the plant.';
      return;
    }
    const text = knob.spec.readout ? knob.spec.readout(latest.value, knob) : '';
    knob.readEl.textContent = text;
  }

  function setOutcome(knob, outcome) {
    knob.statusEl.textContent = outcome?.text ?? '';
    knob.root.dataset.outcome = outcome?.state ?? '';
  }

  // Each knob's model follows the plant when the user is not moving it.
  function syncKnob(knob) {
    if (!latest || knob.dragging || knob.pending) return;
    const { spec } = knob;
    if (spec.kind === 'dial' && knob.model.velocity === 0 && !knob.releasedPending) {
      knob.model = setDial(knob.model, spec.setting(latest.value));
    } else if (spec.kind === 'rotary') {
      const index = spec.setting(latest.value, latest.view);
      if (!knob.releasedPending) knob.model = createRotary(spec.values, index);
    } else if (spec.kind === 'switch') {
      const on = Boolean(spec.setting(latest.value, latest.view));
      if (knob.model.on !== on) knob.model = throwSwitch(knob.model, on);
    }
  }

  function wireDial(knob) {
    const face = knob.face;
    const center = () => {
      const rect = face.getBoundingClientRect();
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    };
    const angleAt = (event) => {
      const c = center();
      return (Math.atan2(event.clientY - c.y, event.clientX - c.x) * 180) / Math.PI;
    };
    listen(face, 'pointerdown', (event) => {
      if (disabledFor(knob)) return;
      face.setPointerCapture?.(event.pointerId);
      knob.dragging = true;
      knob.lastAngle = angleAt(event);
      knob.trail = [{ t: event.timeStamp, deg: 0 }];
      knob.releasedPending = false;
      face.focus();
    });
    listen(face, 'pointermove', (event) => {
      if (!knob.dragging) return;
      const now = angleAt(event);
      let delta = now - knob.lastAngle;
      if (delta > 180) delta -= 360;
      if (delta < -180) delta += 360;
      knob.lastAngle = now;
      const total = (knob.trail.at(-1)?.deg ?? 0) + delta;
      knob.trail.push({ t: event.timeStamp, deg: total });
      if (knob.trail.length > 12) knob.trail.shift();
      knob.model = knob.spec.kind === 'dial' ? turnDial(knob.model, delta) : turnRotary(knob.model, delta);
      paintKnob(knob);
      refreshBoard();
    });
    const release = (event) => {
      if (!knob.dragging) return;
      knob.dragging = false;
      face.releasePointerCapture?.(event.pointerId);
      const velocity = flickVelocity(knob.trail);
      if (knob.spec.kind === 'dial') {
        knob.model = releaseDial(knob.model, velocity);
        if (reducedMotion()) knob.model = settleDial(knob.model);
        knob.releasedPending = true;
        if (knob.model.velocity === 0) settleTurn(knob);
        else requestTick();
      } else {
        knob.model = releaseRotary(knob.model);
        settleTurn(knob);
      }
      paintKnob(knob);
      refreshBoard();
    };
    listen(face, 'pointerup', release);
    listen(face, 'pointercancel', release);
    listen(face, 'keydown', (event) => onDialKey(knob, event));
  }

  /**
   * A settled turn sends its value once, unless the plant already has that value.
   * The plant's value is the one the last snapshot gave.
   */
  function settleTurn(knob) {
    knob.releasedPending = false;
    const value = knob.spec.kind === 'dial' ? dialValue(knob.model) : rotaryValue(knob.model);
    if (latest && value === plantValueOf(knob)) return;
    send(knob, knob.spec.command(value));
  }

  /** The value a dial or rotary has on the plant now, in the units it sends. */
  function plantValueOf(knob) {
    const { spec } = knob;
    if (!latest) return null;
    const setting = spec.setting(latest.value, latest.view);
    return spec.kind === 'dial' ? setting : spec.values[setting];
  }

  function onDialKey(knob, event) {
    if (disabledFor(knob)) return;
    const { spec } = knob;
    if (spec.kind === 'dial') {
      const value = dialValue(knob.model);
      const step = event.shiftKey ? 100 : 10;
      const targets = {
        ArrowUp: value + step,
        ArrowRight: value + step,
        ArrowDown: value - step,
        ArrowLeft: value - step,
        PageUp: value + 100,
        PageDown: value - 100,
        Home: spec.min,
        End: spec.max,
      };
      if (!(event.key in targets)) return;
      event.preventDefault();
      const next = setDial(knob.model, targets[event.key]);
      if (dialValue(next) === value) return;
      knob.model = next;
      paintKnob(knob);
      refreshBoard();
      send(knob, spec.command(dialValue(next)));
      return;
    }
    const index = resolveDetent(knob.model.angle, spec.values, knob.model.sweep).index;
    const targets = {
      ArrowUp: index + 1,
      ArrowRight: index + 1,
      ArrowDown: index - 1,
      ArrowLeft: index - 1,
      Home: 0,
      End: spec.values.length - 1,
    };
    if (!(event.key in targets)) return;
    event.preventDefault();
    const target = Math.min(spec.values.length - 1, Math.max(0, targets[event.key]));
    if (target === index) return;
    knob.model = createRotary(spec.values, target);
    paintKnob(knob);
    refreshBoard();
    send(knob, spec.command(spec.values[target]));
  }

  function onSwitch(knob) {
    if (disabledFor(knob) || knob.pending) return;
    knob.model = toggleSwitch(knob.model);
    if (reducedMotion()) knob.model = advanceSwitch(knob.model, Number.POSITIVE_INFINITY);
    paintKnob(knob);
    refreshBoard();
    requestTick();
    send(knob, knob.spec.command(knob.model.on, latest?.view));
  }

  function wireButton(knob) {
    listen(knob.control, 'pointerdown', (event) => {
      if (disabledFor(knob) || knob.pending) return;
      knob.model = pressButton(knob.model);
      paintKnob(knob);
      refreshBoard();
      requestTick();
    });
    const letGo = () => {
      knob.model = releaseButton(knob.model);
      if (reducedMotion()) knob.model = { ...knob.model, depth: 0 };
      paintKnob(knob);
      refreshBoard();
      requestTick();
    };
    listen(knob.control, 'pointerup', letGo);
    listen(knob.control, 'pointerleave', letGo);
    listen(knob.control, 'click', () => {
      if (disabledFor(knob) || knob.pending) return;
      // A keyboard press has no pointer down, so the cap goes down here and springs back.
      knob.model = releaseButton({ ...pressButton(knob.model), depth: 1 });
      if (reducedMotion()) knob.model = { ...knob.model, depth: 0 };
      paintKnob(knob);
      refreshBoard();
      requestTick();
      send(knob, knob.spec.command());
    });
  }

  /** Posts one command for a knob and shows its pending state, then its reply. */
  async function send(knob, command) {
    if (disposed) return;
    const path = knob.spec.channel === 'faults' ? options.faults : options.command;
    if (!path) {
      setOutcome(knob, { state: 'failed', text: 'Not sent: this control is not connected to the world.' });
      return;
    }
    let body = command;
    if (knob.spec.channel === 'faults') {
      if (!latest) {
        setOutcome(knob, { state: 'failed', text: 'Not sent: the plant has not reported a state yet.' });
        return;
      }
      body = faultCommand(latest.value, command);
    }
    const seq = ++knob.seq;
    knob.pending = true;
    setOutcome(knob, { state: 'pending', text: 'Sending…' });
    paintKnob(knob);
    const outcome = await postCommand(services.transport, path, body, { signal: controller.signal });
    if (disposed || seq !== knob.seq) return; // a newer turn owns the knob now
    knob.pending = false;
    setOutcome(knob, outcome);
    // An applied turn keeps the knob where the user put it until the next snapshot shows it.
    // A refused turn goes back to the plant's state now.
    if (outcome.state === 'refused' || outcome.state === 'failed') syncKnob(knob);
    paintKnob(knob);
    paintReadout(knob);
    refreshBoard();
  }

  // ---- Frame loop: runs only while a knob moves ----------------------------

  function moving(knob) {
    const { model, spec } = knob;
    if (spec.kind === 'dial') return model.velocity !== 0 || knob.releasedPending;
    if (spec.kind === 'switch') return !switchAtRest(model);
    if (spec.kind === 'button') return model.depth !== (model.held ? 1 : 0);
    return false;
  }

  function requestTick() {
    if (tickRaf === 0 && !disposed) {
      lastTick = performance.now();
      tickRaf = requestAnimationFrame(tick);
    }
  }

  function tick(now) {
    tickRaf = 0;
    if (disposed) return;
    const dt = Math.min(0.1, (now - lastTick) / 1000);
    lastTick = now;
    let any = false;
    for (const knob of knobList) {
      const { spec } = knob;
      if (spec.kind === 'dial' && knob.model.velocity !== 0) {
        knob.model = coastDial(knob.model, dt);
      } else if (spec.kind === 'switch' && !switchAtRest(knob.model)) {
        knob.model = advanceSwitch(knob.model, dt);
      } else if (spec.kind === 'button' && moving(knob)) {
        knob.model = advanceButton(knob.model, dt);
      }
      if (moving(knob)) any = true;
      if (spec.kind === 'dial' && knob.releasedPending && knob.model.velocity === 0) settleTurn(knob);
      paintKnob(knob);
    }
    refreshBoard();
    if (any) tickRaf = requestAnimationFrame(tick);
  }

  // ---- Snapshot -----------------------------------------------------------

  function onSnapshot(snapshot) {
    if (disposed) return;
    const value = snapshot.value;
    if (value === null || value === undefined) {
      status.textContent = overlayStatus.textContent = 'The world has not published the plant state yet.';
      return;
    }
    const view = instruments(value);
    latest = { revision: value.revision, value, view };
    showStatus(view);
    showFacts(value, view);
    const alarms = view.alarms.filter(a => a.state === 'active' || a.state === 'acknowledged');
    alarmList.replaceChildren(...(alarms.length ? alarms.map(a => h('li', { text: `${a.label}. ${a.state === 'active' ? 'Active, unacknowledged' : 'Acknowledged'}.` })) : [h('li', { text: 'No alarms.' })]));
    processList.replaceChildren(...(view.processFaults.length ? view.processFaults.map(f => h('li', { text: f.label })) : [h('li', { text: 'No active process faults.' })]));
    for (const knob of knobList) {
      syncKnob(knob);
      paintKnob(knob);
      paintReadout(knob);
    }
    readings?.update(value);
    board?.updatePlant(value);
    refreshBoard();
    requestTick();
  }

  function showStatus(view) {
    const trip = view.reactor.tripped ? `Reactor tripped: ${view.reactor.tripCause}` : 'Reactor not tripped';
    const summary = `${formatClock(view.atMs)} · Neutron power ${formatValue(view.reactor.neutronPowerPercent, '%')} · ${trip} · Telemetry ${view.telemetry.quiet ? 'quiet' : 'live'}`;
    status.textContent = summary;
    overlayStatus.textContent = summary;
  }

  function showFacts(value, view) {
    factValues.time.textContent = formatClock(view.atMs);
    factValues.telemetry.textContent = view.telemetry.quiet ? 'Quiet' : `Live, heartbeat ${view.telemetry.heartbeat}`;
    factValues.revision.textContent = String(value.revision);
    factValues.actions.textContent = String(view.operatorActions);
  }

  /** What the 3D boards need: the view, the text they print and the knob states. */
  function boardInputs() {
    const { view } = latest;
    const held = {};
    for (const pair of view.pairs) {
      if (pair.frozen) held[pair.key] = pair.sampledAtMs === null ? 'Held' : `Held at ${formatClock(pair.sampledAtMs)}`;
    }
    const text = {
      plantTime: formatClock(view.atMs),
      telemetry: view.telemetry.quiet ? 'Telemetry quiet: readings held' : `Telemetry live, heartbeat ${view.telemetry.heartbeat}`,
      held,
    };
    const knobStates = knobList.filter(knob => knob.spec.group === 'plant').map((knob) => {
      const { model, spec } = knob;
      if (spec.kind === 'dial' || spec.kind === 'rotary') return { kind: spec.kind, fraction: model.angle / model.sweep };
      if (spec.kind === 'switch') return { kind: 'switch', travel: model.travel };
      return { kind: 'button', depth: model.depth };
    });
    return { view, text, knobStates };
  }

  function refreshBoard() {
    if (!board || !latest) return;
    const { view, text, knobStates } = boardInputs();
    board.update(view, text, knobStates);
  }

  // ---- Theme and motion ---------------------------------------------------

  function onTheme() {
    if (disposed) return;
    const colors = palette();
    if (!paletteReady(colors)) return;
    board?.setTheme(colors);
    refreshBoard();
  }
  const themeObserver = new MutationObserver(onTheme);
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  listen(darkQuery, 'change', onTheme);
  listen(forcedQuery, 'change', onTheme);
  listen(reduceQuery, 'change', () => {
    // Snap the views to where they are now.
    refreshBoard();
  });

  // ---- 3D and text loading ------------------------------------------------

  const failure = (where, error) => {
    const detail = error?.message ? ` (${error.message})` : '';
    return h('p', { class: 'cr-error', role: 'status', text: `Could not load three.js for the ${where}${detail}. ${LOAD_FAILURE}` });
  };

  let paletteRaf = 0;
  let paletteFrames = 0;
  let started = false;
  const styleMessages = [controlStage].map((stage) => {
    const message = h('p', { role: 'status', text: 'Waiting for view colors.' });
    stage.append(message);
    return message;
  });

  function startViews() {
    if (disposed || started) return;
    if (paletteRaf) cancelAnimationFrame(paletteRaf);
    paletteRaf = 0;
    if (!paletteReady(palette())) {
      if (paletteFrames++ < 300) paletteRaf = requestAnimationFrame(startViews);
      else for (const message of styleMessages) message.textContent = 'View colors could not load. Reload the page to try again.';
      return;
    }
    started = true;
    for (const message of styleMessages) message.remove();

    import('./control-board.mjs').then(
      ({ createControlBoard }) => {
        if (disposed) return;
        board = createControlBoard(controlStage, {
          knobIds: KNOBS.filter(spec => spec.group === 'plant').map(spec => spec.id),
          knobLabels: KNOBS.filter(spec => spec.group === 'plant').map(spec => spec.label),
          theme: palette(),
          reducedMotion,
        });
        board.setView(viewName);
        if (latest) board.updatePlant(latest.value);
        refreshBoard();
      }).catch((error) => {
        if (!disposed) controlStage.append(failure('control room', error));
      });

    import('./plant-scene.mjs').then(
      ({ createReadingsPanel }) => {
        if (disposed) return;
        readings = createReadingsPanel(readingsHost);
        if (latest) {
          readings.update(latest.value);
        }
      }).catch((error) => {
        if (disposed) return;
        readingsHost.append(failure('readings', error));
      });
  }

  for (const link of document.head.querySelectorAll('link[rel="stylesheet"]')) {
    listen(link, 'load', startViews);
  }
  startViews();

  // ---- Subscription and disposal ------------------------------------------

  if (!options.state) {
    status.textContent = overlayStatus.textContent = 'This panel has no plant state topic, so it cannot show the plant.';
  } else {
    unsubscribe = services.state(options.state, onSnapshot, (error) => {
      if (disposed) return;
      status.textContent = overlayStatus.textContent = `Could not read the plant state: ${error.message}`;
    });
  }

  showView(viewName);

  function dispose() {
    if (disposed) return;
    disposed = true;
    controller.abort();
    if (paletteRaf) cancelAnimationFrame(paletteRaf);
    unsubscribe?.();
    unsubscribe = null;
    if (tickRaf) cancelAnimationFrame(tickRaf);
    tickRaf = 0;
    themeObserver.disconnect();
    for (const remove of listeners) remove();
    listeners.length = 0;
    board?.dispose();
    readings?.dispose();
    board = null;
    readings = null;
    root.replaceChildren();
    root.classList.remove('cr-root');
  }

  return dispose;
}

function readPalette(root) {
  const style = getComputedStyle(root);
  const out = {};
  // Resolve system colors before passing them to Three's color parser.
  const swatch = document.createElement('span');
  swatch.hidden = true;
  swatch.style.forcedColorAdjust = 'none';
  root.append(swatch);
  for (const [name, token] of Object.entries(PALETTE_TOKENS)) {
    const color = style.getPropertyValue(token).trim();
    if (color && !color.startsWith('#')) {
      swatch.style.color = color;
      out[name] = getComputedStyle(swatch).color;
    } else out[name] = color;
  }
  swatch.remove();
  return out;
}

/** The release speed of a flick, in degrees per second, from the last 120 ms of the trail. */
export function flickVelocity(trail) {
  if (trail.length < 2) return 0;
  const last = trail.at(-1);
  let first = trail[0];
  for (const sample of trail) {
    if (last.t - sample.t <= 120) {
      first = sample;
      break;
    }
  }
  const seconds = (last.t - first.t) / 1000;
  if (seconds <= 0) return 0;
  return (last.deg - first.deg) / seconds;
}
