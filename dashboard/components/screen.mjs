// mount(root, services, options) -> dispose; shared services are described in README.md.
// A host's screen through noVNC, watching by default. "Take over" asks for the
// host's input lease; services.input says who holds it, for every viewer.
// options.controls, when given, is where the take over button and the owner
// go (a tile header); otherwise they sit above the screen. With
// options.interactive the viewer takes input as soon as the screen connects,
// unless another viewer holds it, and the guest's display follows the size
// of the panel while this viewer holds input.
import { scoped } from '../dom.mjs';
import { mountConsole } from './console.mjs';

export function mount(root, services, options) {
  const { el } = scoped(root);
  const controls = options.controls || el('div', { class: 'console-controls' });
  const owner = el('span', { class: 'console-owner' }, controls);
  const claim = el('button', { class: 'button', type: 'button', text: 'Take over' }, controls);
  claim.hidden = true;
  let active, timer, notice, attempt = 0, mine = false, input = { holder: null, mine: false, owner: 'none', text: '' };

  function ownership() {
    const was = mine;
    mine = Boolean(active?.connected && input.mine);
    if (active?.rfb) {
      active.rfb.viewOnly = !mine;
      if (options.interactive) active.rfb.resizeSession = mine;
    }
    claim.hidden = !active?.connected || Boolean(options.interactive && (!input.holder || mine));
    claim.textContent = mine ? 'Release' : 'Take over';
    owner.textContent = options.interactive && mine ? '' : input.text;
    owner.dataset.owner = input.owner;
    if (was && !mine && input.holder && active?.connected) {
      // Input is already off: the lease moved to another viewer.
      owner.textContent = 'Another viewer took control';
      clearTimeout(notice);
      notice = setTimeout(ownership, 4000);
    }
  }
  function lost(panel, reason) {
    panel.stop();
    if (panel.disposed || !panel.available || panel.missing || panel.ended()) return;
    const seconds = Math.min(30, 4 * 2 ** attempt++);
    panel.show(`${reason ? `${reason}. ` : 'Connection lost. '}Reconnecting in ${seconds} s`, true);
    timer = setTimeout(() => panel.open(), seconds * 1000);
  }
  async function open(panel) {
    const current = panel.generation, controller = new AbortController();
    const entry = active = { controller };
    panel.show('Connecting to the screen…');
    try {
      const { socket, session } = await services.transport.socket('screen', options.host, controller.signal);
      if (panel.disposed || current !== panel.generation) { socket.close(); return; }
      entry.socket = socket;
      entry.session = session;
      const rfb = entry.rfb = new panel.library.default(panel.display, socket);
      rfb.scaleViewport = true;
      rfb.resizeSession = false;
      rfb.background = 'transparent';
      rfb.viewOnly = true;
      const connected = () => {
        if (current !== panel.generation) return;
        entry.connected = true;
        attempt = 0;
        panel.hide();
        services.input.session(options.host, entry.session);
        ownership();
        if (options.interactive && !input.holder) void takeover(false);
      };
      const disconnected = () => {
        entry.disconnected = true;
        if (current === panel.generation) lost(panel);
      };
      const closed = (event) => { if (current === panel.generation) lost(panel, event.reason); };
      rfb.addEventListener('connect', connected);
      rfb.addEventListener('disconnect', disconnected);
      socket.addEventListener('close', closed);
      entry.cleanup = () => {
        rfb.removeEventListener('connect', connected);
        rfb.removeEventListener('disconnect', disconnected);
        socket.removeEventListener('close', closed);
      };
      ownership();
    } catch (error) {
      if (!panel.disposed && current === panel.generation) lost(panel, error.message);
    }
  }
  function close() {
    clearTimeout(timer);
    const old = active;
    active = null;
    if (old?.connected) services.input.session(options.host, null);
    old?.cleanup?.();
    old?.controller.abort();
    // noVNC logs an error when an RFB that already disconnected is told to.
    if (old?.rfb && !old.disconnected) old.rfb.disconnect();
    old?.socket?.close();
    ownership();
  }
  const { panel, dispose } = mountConsole(root, services, options, {
    kind: 'screen', display: 'screen-display', retry: 'Reconnect now', open, close,
    waiting: (state) => (state === 'network_up' || state === 'ssh_up'
      ? `${options.host} is up. The screen opens when its desktop is ready.`
      : `${options.host} is booting. The screen opens when its desktop is up.`),
    load: () => services.importModule('/vendor/novnc/core/rfb.js').catch(() => { throw new Error('noVNC'); }),
  });
  if (!options.controls) root.insertBefore(controls, root.firstChild);
  async function takeover(take = true) {
    const current = active;
    if (!current?.connected) return;
    claim.disabled = true;
    try {
      const release = input.holder === current.session;
      const reply = await services.transport[release ? 'delete' : 'post']('/api/lease', {
        host: options.host, session: current.session, ...(release ? {} : { take: take !== false }),
      }, current.controller.signal);
      // The lease topic owns input permission, including a takeover during this reply.
      if (active !== current) return;
      if (reply.holder !== current.session) current.rfb.viewOnly = true;
    } catch (error) {
      if (active !== current) return;
      owner.textContent = `Input control unavailable: ${error.message}`;
    } finally {
      claim.disabled = false;
    }
  }
  const click = () => takeover();
  claim.addEventListener('click', click);
  const offInput = services.input.subscribe(options.host, (value) => { input = value; ownership(); });
  return () => {
    if (!dispose()) return;
    offInput();
    clearTimeout(notice);
    claim.removeEventListener('click', click);
    controls.replaceChildren();
  };
}
