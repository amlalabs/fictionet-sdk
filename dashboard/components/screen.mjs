// mount(root, services, options) -> dispose; shared services are described in README.md.
// A host's screen through noVNC, watching by default. "Take over" asks for the
// host's input lease; the lease topic says who holds it, for every viewer.
// options.controls, when given, is where the take over button and the owner
// go (a tile header); otherwise they sit above the screen. options.onSession
// hears this tab's screen session while it is connected, and null after.
export function mount(root, services, options) {
  const document = root.ownerDocument;
  const { setTimeout = globalThis.setTimeout, clearTimeout = globalThis.clearTimeout } = services;
  const make = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  };
  const controls = options.controls || make('div', 'console-controls');
  const owner = make('span', 'console-owner'), claim = make('button', 'button', 'Take over');
  const stage = make('div', 'console-stage'), display = make('div', 'screen-display');
  const card = make('div', 'console-card'), message = make('p', '', 'Loading the screen…');
  const reconnect = make('button', 'button', 'Reconnect now');
  claim.type = reconnect.type = 'button';
  message.setAttribute('role', 'status');
  claim.hidden = true;
  reconnect.hidden = true;
  card.append(message, reconnect);
  stage.append(display, card);
  controls.append(owner, claim);
  root.classList.add('console-panel');
  if (!options.controls) root.append(controls);
  root.append(stage);
  let disposed = false, available = false, missing = false, RFB, active, timer, notice, attempt = 0, generation = 0;
  let holder = null, mine = false;

  function show(text, retry = false) {
    message.textContent = text;
    card.hidden = false;
    reconnect.hidden = !retry;
  }
  function ownership() {
    const was = mine;
    mine = Boolean(active?.session && holder === active.session);
    if (active?.rfb) active.rfb.viewOnly = !mine;
    claim.hidden = !active?.connected;
    claim.textContent = mine ? 'Release' : 'Take over';
    const text = mine ? 'You have control' : holder ? 'Another viewer has control' : 'Watching';
    owner.textContent = text === 'Watching' ? '' : text;
    owner.dataset.owner = mine ? 'mine' : holder ? 'other' : 'none';
    options.onOwnership?.(text);
    if (was && !mine && holder && active?.connected) {
      // Input is already off: the lease topic moved to another viewer.
      owner.textContent = 'Another viewer took control';
      clearTimeout(notice);
      notice = setTimeout(ownership, 4000);
    }
  }
  function stop() {
    generation++;
    clearTimeout(timer);
    const old = active;
    active = null;
    if (old?.connected) options.onSession?.(null);
    old?.cleanup?.();
    old?.controller.abort();
    // noVNC logs an error when an RFB that already disconnected is told to.
    if (old?.rfb && !old.disconnected) old.rfb.disconnect();
    old?.socket?.close();
    display.replaceChildren();
    ownership();
  }
  const CLOSED = 'The screen closed when the run stopped.';
  function lost(reason) {
    stop();
    if (disposed || !available || missing) return;
    if (services.stopped?.()) { show(CLOSED); return; }
    const seconds = Math.min(30, 4 * 2 ** attempt++);
    show(`${reason ? `${reason}. ` : 'Connection lost. '}Reconnecting in ${seconds} s`, true);
    timer = setTimeout(connect, seconds * 1000);
  }
  async function connect() {
    if (disposed || !available || !RFB) return;
    stop();
    const current = generation, controller = new AbortController();
    const entry = active = { controller };
    show('Connecting to the screen…');
    try {
      const { socket, session } = await services.transport.socket('screen', options.host, controller.signal);
      if (disposed || current !== generation) { socket.close(); return; }
      entry.socket = socket;
      entry.session = session;
      const rfb = entry.rfb = new RFB(display, socket);
      rfb.scaleViewport = true;
      rfb.resizeSession = false;
      rfb.background = 'transparent';
      rfb.viewOnly = true;
      const connected = () => {
        if (current !== generation) return;
        entry.connected = true;
        attempt = 0;
        card.hidden = true;
        options.onSession?.(entry.session);
        ownership();
      };
      const disconnected = () => {
        entry.disconnected = true;
        if (current === generation) lost();
      };
      const closed = (event) => { if (current === generation) lost(event.reason); };
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
      if (!disposed && current === generation) lost(error.message);
    }
  }
  async function takeover() {
    const current = active;
    if (!current?.connected) return;
    claim.disabled = true;
    try {
      const release = holder === current.session;
      const reply = await services.transport[release ? 'delete' : 'post']('/api/lease', {
        host: options.host, session: current.session, ...(release ? {} : { take: true }),
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
  claim.addEventListener('click', takeover);
  reconnect.addEventListener('click', connect);
  const offLease = services.state('/api/state/leases', (snapshot) => {
    holder = snapshot.value?.[options.host]?.holder ?? null;
    ownership();
  }, (error) => {
    holder = null;
    ownership();
    owner.textContent = `Input control unavailable: ${error.message}`;
  });
  const offStatus = services.state(options.status || `/api/state/host-${options.host}`, (snapshot) => {
    const wasAvailable = available;
    available = Boolean(snapshot.value?.screen);
    if (!available) {
      stop();
      const state = snapshot.value?.state;
      if (!missing) show(state === 'stopped' ? `${options.host} has stopped.`
        : state === 'network_up' || state === 'ssh_up' ? `${options.host} is up. The screen opens when its desktop is ready.`
        : `${options.host} is booting. The screen opens when its desktop is up.`);
    } else if (!wasAvailable) void connect();
  }, (error) => {
    available = false;
    stop();
    show(`Screen status unavailable: ${error.message}. Reload the demo to retry.`);
  });
  const load = options.load || (() => import('/vendor/novnc/core/rfb.js'));
  void load().then((module) => {
    if (disposed) return;
    RFB = module.default;
    void connect();
  }).catch(() => {
    if (disposed) return;
    missing = true;
    show(services.stopped?.() ? CLOSED : 'noVNC is not in this build. Run `cargo xtask demo libraries`, then rebuild.');
  });
  return () => {
    if (disposed) return;
    disposed = true;
    offLease();
    offStatus();
    clearTimeout(notice);
    stop();
    claim.removeEventListener('click', takeover);
    reconnect.removeEventListener('click', connect);
    controls.replaceChildren();
    root.replaceChildren();
    root.classList.remove('console-panel');
  };
}
