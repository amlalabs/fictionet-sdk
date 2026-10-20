// Knob behavior for the control room: how each knob feels and what it sends.
//
// This module is pure: no DOM, no Three.js, no clock. Each function takes a
// knob's state and, where it moves, a time in seconds, and returns the next
// state. The feel is cosmetic. A dial coasts after a flick, a switch throws
// between two firm stops, a pushbutton springs back. The value a knob sends
// comes only from its settled state, in whole steps, so the command is exact.
//
// Commands use the plant's serde forms (examples/nuclear/world/src/command.rs
// and faults.rs). Rod positions are tenths of a percent. Valve demands are
// permille. Hot leg counts are tenths of a degree C.
//
// Replies: the world answers a posted command with the page's reply
// (applied, rejected, pending or timeout). An accepted plant command replies
// with the serde form of Result<Applied, Rejected>, so a refusal is the
// `Err` form, and its reason says why the plant refused.

/** Travel of a large dial from its minimum stop to its maximum stop, in degrees. */
export const DIAL_SWEEP_DEG = 300;
/** Travel of a rotary from its first detent to its last, in degrees. */
export const ROTARY_SWEEP_DEG = 240;
/** How far a rotary's hand can pass its end detents, in degrees. */
export const ROTARY_TRAVEL_DEG = 12;
/** Linear slowing of a released dial, in degrees per second squared. */
export const COAST_DECEL_DEG_S2 = 480;
/** The fastest a release can carry a dial, in degrees per second. */
export const MAX_FLICK_DEG_S = 1440;
/** Seconds for a switch to throw from one firm stop to the other. */
export const THROW_S = 0.3;
/** Seconds for a pushbutton to bottom out, and to spring back. */
export const PRESS_S = 0.04;
export const SPRING_S = 0.12;
/** Degrees C per count of a hot leg sensor (sensors.rs gives 0.1 C). */
export const HOT_LEG_RESOLUTION_C = 0.1;

const clamp = (value, low, high) => Math.min(high, Math.max(low, value));

function wholeIn(value, low, high, name) {
  if (!Number.isInteger(value) || value < low || value > high) {
    throw new RangeError(`${name} must be a whole number from ${low} to ${high}`);
  }
  return value;
}

// Large setpoint dial with inertia. The angle is the state; the value is the
// angle read as whole steps between the minimum and maximum.

/**
 * A dial from `min` to `max` in whole `step`s, set to `value`. The range must
 * be a whole number of steps.
 */
export function createDial({ min, max, step = 1, value = min, sweep = DIAL_SWEEP_DEG }) {
  if (!(max > min) || !(step > 0) || !Number.isInteger((max - min) / step)) {
    throw new RangeError('a dial needs max above min and a step that divides the range');
  }
  return setDial({ min, max, step, sweep, angle: 0, velocity: 0 }, value);
}

/** The exact value a dial shows and sends: its angle read as whole steps. */
export function dialValue(dial) {
  const steps = Math.round((dial.angle / dial.sweep) * ((dial.max - dial.min) / dial.step));
  return dial.min + steps * dial.step;
}

/** The dial at rest on `value`. A value past a limit stops at that limit. */
export function setDial(dial, value) {
  const fraction = (clamp(value, dial.min, dial.max) - dial.min) / (dial.max - dial.min);
  return { ...dial, angle: fraction * dial.sweep, velocity: 0 };
}

/** The dial moved by the pointer, in degrees, and held on its stops. */
export function turnDial(dial, deltaDeg) {
  return { ...dial, angle: clamp(dial.angle + deltaDeg, 0, dial.sweep), velocity: 0 };
}

/** The dial let go while it moves at `velocity` degrees per second. */
export function releaseDial(dial, velocity) {
  return { ...dial, velocity: clamp(velocity, -MAX_FLICK_DEG_S, MAX_FLICK_DEG_S) };
}

function stopOn(dial, angle, velocity) {
  if (angle <= 0) return { ...dial, angle: 0, velocity: 0 };
  if (angle >= dial.sweep) return { ...dial, angle: dial.sweep, velocity: 0 };
  return { ...dial, angle, velocity };
}

/**
 * A released dial moved on by `dt` seconds. Its speed falls at a steady rate
 * and stops exactly at zero. A dial that reaches a stop stops there.
 */
export function coastDial(dial, dt) {
  if (dial.velocity === 0 || dt <= 0) return dial;
  const v0 = dial.velocity;
  const stopIn = Math.abs(v0) / COAST_DECEL_DEG_S2;
  if (stopIn <= dt) {
    return stopOn(dial, dial.angle + (v0 * stopIn) / 2, 0);
  }
  const v1 = v0 - Math.sign(v0) * COAST_DECEL_DEG_S2 * dt;
  return stopOn(dial, dial.angle + ((v0 + v1) / 2) * dt, v1);
}

/** A released dial run to rest in one step, to the same place as coastDial. */
export function settleDial(dial) {
  if (dial.velocity === 0) return dial;
  const travel = (dial.velocity * Math.abs(dial.velocity)) / (2 * COAST_DECEL_DEG_S2);
  return stopOn(dial, dial.angle + travel, 0);
}

// Rotary with detents. The hand's angle is the state. It snaps to the nearest
// detent on release. A detent value is what the knob sends.

/** The angle of each detent, spread evenly over the sweep. */
export function detentAngles(count, sweep = ROTARY_SWEEP_DEG) {
  if (!Number.isInteger(count) || count < 2) throw new RangeError('a rotary needs at least two detents');
  return Array.from({ length: count }, (_, i) => (i * sweep) / (count - 1));
}

/**
 * The detent nearest an angle: its index, value and angle. A halfway angle goes
 * to the lower detent, so the choice is always one detent.
 */
export function resolveDetent(angle, values, sweep = ROTARY_SWEEP_DEG) {
  const angles = detentAngles(values.length, sweep);
  let index = 0;
  let best = Infinity;
  angles.forEach((detent, i) => {
    const distance = Math.abs(angle - detent);
    if (distance < best) {
      best = distance;
      index = i;
    }
  });
  return { index, value: values[index], angle: angles[index] };
}

/** A rotary with `values` as its detents, set to the detent at `index`. */
export function createRotary(values, index = 0, sweep = ROTARY_SWEEP_DEG) {
  const angle = detentAngles(values.length, sweep)[wholeIn(index, 0, values.length - 1, 'index')];
  return { values, sweep, angle };
}

/** The rotary's hand turned by the pointer, with a little travel past its end detents. */
export function turnRotary(rotary, deltaDeg) {
  const angle = clamp(rotary.angle + deltaDeg, -ROTARY_TRAVEL_DEG, rotary.sweep + ROTARY_TRAVEL_DEG);
  return { ...rotary, angle };
}

/** The rotary let go: the hand moves to the nearest detent. */
export function releaseRotary(rotary) {
  return { ...rotary, angle: resolveDetent(rotary.angle, rotary.values, rotary.sweep).angle };
}

/** The value of the detent the rotary's hand is nearest. */
export function rotaryValue(rotary) {
  return resolveDetent(rotary.angle, rotary.values, rotary.sweep).value;
}

// Switch with two firm stops. Travel runs from 0 (off stop) to 1 (on stop) and
// never goes past either.

/** A switch at rest on its off stop, or on its on stop when `on` is true. */
export function createSwitch(on = false) {
  return { on: Boolean(on), travel: on ? 1 : 0 };
}

/** The switch thrown toward a stop. It moves when time is advanced. */
export function throwSwitch(sw, on) {
  return { ...sw, on: Boolean(on) };
}

/** The switch thrown toward the stop it is not heading to. */
export function toggleSwitch(sw) {
  return throwSwitch(sw, !sw.on);
}

/** The stop the switch is at or heading to: 'on' or 'off'. */
export function switchStop(sw) {
  return sw.on ? 'on' : 'off';
}

/** True once the switch has reached the stop it was thrown toward. */
export function switchAtRest(sw) {
  return sw.travel === (sw.on ? 1 : 0);
}

/** The switch moved on by `dt` seconds of travel. */
export function advanceSwitch(sw, dt) {
  const goal = sw.on ? 1 : 0;
  const step = dt / THROW_S;
  const travel = goal > sw.travel ? Math.min(goal, sw.travel + step) : Math.max(goal, sw.travel - step);
  return { ...sw, travel: clamp(travel, 0, 1) };
}

// Pushbutton. It is held down, bottoms out, and springs back when let go.

/** A pushbutton at rest, not held. */
export function createButton() {
  return { held: false, depth: 0 };
}

/** The button held down. */
export function pressButton(button) {
  return { ...button, held: true };
}

/** The button let go. */
export function releaseButton(button) {
  return { ...button, held: false };
}

/** The button moved on by `dt` seconds: it bottoms out while held and springs back when let go. */
export function advanceButton(button, dt) {
  const goal = button.held ? 1 : 0;
  const span = button.held ? PRESS_S : SPRING_S;
  const step = dt / span;
  const depth = goal > button.depth ? Math.min(goal, button.depth + step) : Math.max(goal, button.depth - step);
  return { ...button, depth: clamp(depth, 0, 1) };
}

/** Closing the guard also rearms the next covered press. */
export function coverState() {
  return { open: false, fired: false };
}

/** Open first, then trip once. Another trip needs a closed guard first. */
export function pressCover(state) {
  if (!state.open) return { state: { open: true, fired: false }, command: null };
  if (state.fired) return { state, command: null };
  return { state: { open: true, fired: true }, command: plant.manualTrip() };
}

// Commands. Each builder returns the value a knob posts as `command`.

/** Plant commands in the world's serde forms. */
export const plant = Object.freeze({
  /** Rod demand in tenths of a percent, 0 to 1000. */
  rodDemand: (tenths) => ({ rod_demand: { tenths_percent: wholeIn(tenths, 0, 1000, 'rod demand') } }),
  manualTrip: () => 'manual_trip',
  resetTrip: () => 'reset_trip',
  acknowledgeAlarms: () => 'acknowledge_alarms',
  /** `pump` is a serde pump, such as {"coolant":"a"} or "circulating_water". */
  pump: (pump, running) => ({ pump: { pump, running: Boolean(running) } }),
  /** `valve` is a serde valve, such as {"feed":"a"} or "turbine". Demand is permille, 0 to 1000. */
  valveDemand: (valve, permille) => ({ valve_demand: { valve, permille: wholeIn(permille, 0, 1000, 'valve demand') } }),
  /** `controller` is a serde controller and `mode` is "automatic" or "manual". */
  controller: (controller, mode) => ({ controller: { controller, mode } }),
  heaters: (on) => ({ heaters: { on: Boolean(on) } }),
});

/** Fault changes in the world's serde forms, for a switch thrown on or off. */
export const fault = Object.freeze({
  telemetryQuiet: (on) => (on ? { inject: 'telemetry_quiet' } : { clear: 'telemetry_quiet' }),
  condenserCoolingLoss: (on) => {
    const process = { process: 'condenser_cooling_loss' };
    return on ? { inject: process } : { clear: process };
  },
  /** A coolant pump trip for loop 'a' or 'b'. */
  coolantPumpTrip: (loop, on) => {
    const process = { process: { coolant_pump_trip: { pump: loop } } };
    return on ? { inject: process } : { clear: process };
  },
  /**
   * A hot leg sensor stuck at `count`, in counts of HOT_LEG_RESOLUTION_C. Off
   * clears the stuck sensor.
   */
  stuckHotLeg: (loop, count, on) => {
    const sensor = { sensor: { hot_leg: loop } };
    return on
      ? { inject: { sensor: { sensor: { hot_leg: loop }, kind: { stuck: { value: wholeIn(count, -32768, 32767, 'count') } } } } }
      : { clear: sensor };
  },
  clearAll: () => 'clear_all',
});

/** The count a hot leg sensor reads at a temperature in degrees C. */
export function hotLegCount(celsius) {
  return Math.round(celsius / HOT_LEG_RESOLUTION_C);
}

/**
 * A fault change carrying the revision of the snapshot it was made from.
 * `snapshot` is the PlantSnapshot value. The world refuses a turn made from
 * an older revision.
 */
export function faultCommand(snapshot, change) {
  return { change, expected_revision: wholeIn(snapshot.revision, 0, Number.MAX_SAFE_INTEGER, 'revision') };
}

/** The body a knob posts to the control port. */
export function commandRequest(command, requestId) {
  if (typeof requestId !== 'string' || requestId === '') throw new TypeError('a request needs an ID');
  return { request_id: requestId, command };
}

const REFUSALS = Object.freeze({
  stale_revision: 'the plant changed before this turn arrived',
  out_of_range: 'the value is outside the range the plant accepts',
  tripped: 'the reactor has tripped',
  trip_condition_present: 'a trip condition is still present',
  faulted: 'that equipment has a fault',
  wrong_mode: 'the controller is in the other mode',
  already_active: 'that is already in effect',
  not_active: 'there is nothing to reset',
  unavailable: 'the world is not taking commands right now',
});

function refused(rejection) {
  const reason = rejection?.reason;
  const detail = reason === 'invalid' ? rejection.message : REFUSALS[reason] ?? String(reason ?? 'unknown reason');
  return { state: 'refused', text: `Refused: ${detail}.` };
}

/**
 * What a knob shows for a reply: 'applied', 'refused', 'pending', 'no-reply'
 * or 'failed', with a line of text for the knob's status.
 */
export function outcomeOf(reply) {
  switch (reply?.status) {
    case 'applied':
      return reply.reply?.Err ? refused(reply.reply.Err) : { state: 'applied', text: 'Applied.' };
    case 'rejected':
      return refused(reply.rejection);
    case 'pending':
      return { state: 'pending', text: 'Sending.' };
    case 'timeout':
      return { state: 'no-reply', text: 'No reply yet. It may still apply. Read the state before trying again.' };
    default:
      return { state: 'failed', text: 'Not sent: the reply was not understood.' };
  }
}

/**
 * Posts a command through the page's transport and returns what the knob
 * shows. The transport rejects a reply that is not 2xx, and its body is the
 * command reply. Nothing here touches the DOM.
 */
export async function postCommand(transport, path, command, { requestId = globalThis.crypto.randomUUID(), signal } = {}) {
  const body = commandRequest(command, requestId);
  try {
    return outcomeOf(await transport.post(path, body, signal));
  } catch (error) {
    if (error?.body) return outcomeOf(error.body);
    return { state: 'failed', text: `Not sent: ${error?.message ?? 'the request failed'}.` };
  }
}
