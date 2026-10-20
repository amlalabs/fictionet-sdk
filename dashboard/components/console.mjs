// The part a host's screen and terminal share: the stage with its status
// card, the host's status topic, loading the console's library, the
// connection generation, and disposal. screen.mjs and terminal.mjs fill in
// how a connection opens and closes.
//
// `parts` gives:
//   kind       'screen' or 'terminal', the host status flag that offers it
//   display    the class of the element the console draws into
//   retry      the label of the card's reconnect button
//   waiting(state)  what the card says while the host does not offer it
//   load()     resolves to the library, or rejects with its name
//   open(panel)     connects; called when the host offers the console and
//                   the library has loaded, and when the viewer asks again
//   close(panel)    ends the connection `open` made, if any
//   unavailable(panel)  optional; the host stopped offering the console
import { scoped } from '../dom.mjs';

export function mountConsole(root, services, options, parts) {
  const { el } = scoped(root);
  const name = parts.kind;
  const stage = el('div', { class: 'console-stage' });
  const display = el('div', { class: parts.display }, stage);
  const card = el('div', { class: 'console-card' }, stage);
  const message = el('p', { role: 'status', text: `Loading the ${name}…` }, card);
  const retry = el('button', { class: 'button', type: 'button', text: parts.retry }, card);
  retry.hidden = true;
  root.classList.add('console-panel');
  root.append(stage);
  const closed = `The ${name} closed when the run stopped.`;
  const panel = {
    display, disposed: false, available: false, missing: false, library: null,
    // Each connection attempt gets a number; work that finishes for an
    // older one is dropped.
    generation: 0,
    show(text, again = false) {
      message.textContent = text;
      card.hidden = false;
      retry.hidden = !again;
    },
    hide() { card.hidden = true; },
    // Ends the connection, if any, and makes later work for it stale.
    stop() {
      panel.generation++;
      parts.close(panel);
      display.replaceChildren();
    },
    // Says the console closed if the run has stopped, and whether it did.
    ended() {
      if (!services.stopped()) return false;
      panel.show(closed);
      return true;
    },
    // Connects when the host offers the console and the library is here.
    open() {
      if (panel.disposed || !panel.available || !panel.library) return;
      panel.stop();
      void parts.open(panel);
    },
  };
  const reconnect = () => panel.open();
  retry.addEventListener('click', reconnect);
  const offStatus = services.state(options.status || `/api/state/host-${options.host}`, (snapshot) => {
    const was = panel.available;
    panel.available = Boolean(snapshot.value?.[parts.kind]);
    if (!panel.available) {
      parts.unavailable?.(panel);
      panel.stop();
      if (!panel.missing) {
        const state = snapshot.value?.state;
        panel.show(state === 'stopped' ? `${options.host} has stopped.` : parts.waiting(state));
      }
    } else if (!was) panel.open();
  }, (error) => {
    panel.available = false;
    parts.unavailable?.(panel);
    panel.stop();
    panel.show(`${name[0].toUpperCase()}${name.slice(1)} status unavailable: ${error.message}. Reload the demo to retry.`);
  });
  parts.load().then((library) => {
    if (panel.disposed) return;
    panel.library = library;
    panel.open();
  }).catch((error) => {
    if (panel.disposed) return;
    panel.missing = true;
    if (!panel.ended()) panel.show(`${error.message} is not in this build. Run \`cargo xtask demo libraries\`, then rebuild.`);
  });
  return {
    panel,
    dispose() {
      if (panel.disposed) return false;
      panel.disposed = true;
      offStatus();
      panel.stop();
      retry.removeEventListener('click', reconnect);
      root.replaceChildren();
      root.classList.remove('console-panel');
      return true;
    },
  };
}

/// Who holds each host's input, from the `leases` state topic and the
/// sessions this tab's screens report. `subscribe(host, listener)` calls
/// `listener({ holder, mine, owner, text })` now and on every change, and
/// returns an unsubscribe function. `owner` is `mine`, `other` or `none`;
/// `text` says so for the viewer, and is empty when no viewer holds input.
/// `session(host, id)` reports this tab's screen session for a host, or null
/// once it closes.
export function createInputOwners(state) {
  const sessions = new Map(), listeners = new Set();
  let leases = {}, failure = null, stop = null;
  function ownerOf(host) {
    if (failure) return { holder: null, mine: false, owner: 'none', text: `Input control unavailable: ${failure.message}` };
    const holder = leases[host]?.holder ?? null;
    const mine = Boolean(holder) && holder === sessions.get(host);
    return { holder, mine, owner: mine ? 'mine' : holder ? 'other' : 'none', text: mine ? 'You have control' : holder ? 'Another viewer has control' : '' };
  }
  const announce = () => { for (const entry of [...listeners]) entry.listener(ownerOf(entry.host)); };
  return {
    subscribe(host, listener) {
      const entry = { host, listener };
      listeners.add(entry);
      stop ??= state('/api/state/leases', ({ value }) => { leases = value || {}; failure = null; announce(); }, (error) => { failure = error; announce(); });
      listener(ownerOf(host));
      return () => {
        listeners.delete(entry);
        if (!listeners.size) { stop?.(); stop = null; }
      };
    },
    session(host, id) {
      if (id) sessions.set(host, id); else sessions.delete(host);
      announce();
    },
  };
}
