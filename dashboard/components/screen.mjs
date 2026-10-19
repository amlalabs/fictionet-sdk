// mount(root, services, options) -> dispose; shared services are described in README.md.
export function mount(root, services, options) {
  const document = root.ownerDocument;
  const { setTimeout = globalThis.setTimeout, clearTimeout = globalThis.clearTimeout } = services;
  const make = (tag, text) => { const node = document.createElement(tag); if (text) node.textContent = text; return node; };
  const controls = make('div'), claim = make('button', 'Take over'), owner = make('span', 'Watching');
  const message = make('p', 'Loading screen…'), reconnect = make('button', 'Reconnect now'), display = make('div');
  controls.className = 'console-controls';
  display.className = 'screen-display';
  root.classList.add('console-panel');
  message.setAttribute('role', 'status');
  claim.disabled = true;
  reconnect.hidden = true;
  controls.append(claim, owner);
  root.append(controls, message, reconnect, display);
  let disposed = false, available = false, missing = false, RFB, active, timer, attempt = 0, generation = 0;
  let holder = null;

  function ownership() {
    const mine = Boolean(active?.session && holder === active.session);
    if (active?.rfb) active.rfb.viewOnly = !mine;
    claim.textContent = mine ? 'Release' : 'Take over';
    claim.disabled = !active?.connected;
    owner.textContent = mine ? 'You have control' : holder ? 'Another viewer has control' : 'Watching';
    options.onOwnership?.(owner.textContent);
  }
  function stop() {
    generation++;
    clearTimeout(timer);
    const old = active;
    active = null;
    old?.cleanup?.();
    old?.controller.abort();
    old?.rfb?.disconnect();
    old?.socket?.close();
    display.replaceChildren();
    ownership();
  }
  function lost(reason) {
    stop();
    if (disposed || !available || missing) return;
    const seconds = Math.min(30, 4 * 2 ** attempt++);
    message.hidden = false;
    message.textContent = `${reason || 'Connection lost.'} Reconnecting in ${seconds} s`;
    reconnect.hidden = false;
    timer = setTimeout(connect, seconds * 1000);
  }
  async function connect() {
    if (disposed || !available || !RFB) return;
    stop();
    const current = generation, controller = new AbortController();
    active = { controller };
    message.hidden = false;
    message.textContent = 'Connecting screen…';
    reconnect.hidden = true;
    try {
      const { socket, session } = await services.transport.socket('screen', options.host, controller.signal);
      if (disposed || current !== generation) { socket.close(); return; }
      active.socket = socket;
      active.session = session;
      const rfb = active.rfb = new RFB(display, socket);
      rfb.scaleViewport = true;
      rfb.resizeSession = false;
      rfb.background = 'var(--sunken)';
      rfb.viewOnly = true;
      const connected = () => {
        if (current !== generation) return;
        active.connected = true;
        attempt = 0;
        message.hidden = true;
        ownership();
      };
      const disconnected = () => { if (current === generation) lost(); };
      const closed = (event) => { if (current === generation) lost(event.reason); };
      rfb.addEventListener('connect', connected);
      rfb.addEventListener('disconnect', disconnected);
      socket.addEventListener('close', closed);
      active.cleanup = () => {
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
      const mine = holder === current.session;
      const reply = await services.transport[mine ? 'delete' : 'post']('/api/lease', {
        host: options.host, session: current.session, ...(mine ? {} : { take: true }),
      }, current.controller.signal);
      // The state stream owns input permission, including a takeover during this reply.
      if (active !== current) return;
      if (reply.holder !== current.session) current.rfb.viewOnly = true;
    } catch (error) {
      if (active !== current) return;
      message.hidden = false;
      message.textContent = `Input control unavailable: ${error.message}`;
    } finally {
      if (active === current) claim.disabled = false;
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
    message.hidden = false;
    message.textContent = `Input control unavailable: ${error.message}`;
  });
  const offStatus = services.state(options.status || `/api/state/host-${options.host}`, (snapshot) => {
    const wasAvailable = available;
    available = Boolean(snapshot.value?.screen);
    if (!available) {
      stop();
      if (!missing) {
        message.hidden = false;
        message.textContent = `${options.host} is ${snapshot.value?.state === 'stopped' ? 'stopped' : 'booting'}. The screen opens when its desktop is up.`;
      }
      reconnect.hidden = true;
    } else if (!wasAvailable) void connect();
  }, (error) => {
    available = false;
    stop();
    message.hidden = false;
    reconnect.hidden = true;
    message.textContent = `Screen status unavailable: ${error.message}. Reload the demo to retry.`;
  });
  const load = options.load || (() => import('/vendor/novnc/core/rfb.js'));
  void load().then((module) => {
    if (disposed) return;
    RFB = module.default;
    void connect();
  }).catch(() => {
    if (disposed) return;
    missing = true;
    message.textContent = 'noVNC is not in this build. Run `cargo xtask demo assets`, then rebuild.';
  });
  return () => {
    if (disposed) return;
    disposed = true;
    offLease();
    offStatus();
    stop();
    claim.removeEventListener('click', takeover);
    reconnect.removeEventListener('click', connect);
    root.replaceChildren();
    root.classList.remove('console-panel');
  };
}
