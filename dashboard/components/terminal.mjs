// mount(root, services, options) -> dispose; shared services are described in README.md.
// A shell on the host through xterm.js. Output is acknowledged after xterm
// has written it, so the page server stops reading when the browser lags.
export function mount(root, services, options) {
  const document = root.ownerDocument;
  const make = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  };
  const stage = make('div', 'console-stage'), display = make('div', 'terminal-display');
  const card = make('div', 'console-card'), message = make('p', '', 'Loading the terminal…');
  const reconnect = make('button', 'button', 'Reconnect'), css = make('link');
  css.rel = 'stylesheet';
  css.href = '/vendor/xterm/css/xterm.css';
  reconnect.type = 'button';
  reconnect.hidden = true;
  message.setAttribute('role', 'status');
  card.append(message, reconnect);
  stage.append(display, card);
  root.classList.add('console-panel');
  root.append(css, stage);
  let disposed = false, available = false, missing = false, constructors, active, generation = 0;
  const ResizeObserver = options.ResizeObserver || globalThis.ResizeObserver;
  const theme = () => {
    const style = (options.getComputedStyle || globalThis.getComputedStyle)(display);
    return { background: style.backgroundColor, foreground: style.color, cursor: style.color };
  };
  function show(text, retry = false) {
    message.textContent = text;
    card.hidden = false;
    reconnect.hidden = !retry;
  }
  function stop() {
    generation++;
    const old = active;
    active = null;
    old?.cleanup?.();
    old?.controller.abort();
    old?.socket?.close();
    old?.observer?.disconnect();
    old?.terminal?.dispose();
    display.replaceChildren();
  }
  function disconnected(reason) {
    stop();
    if (disposed || !available) return;
    show(reason ? `Disconnected: ${reason}.` : 'Disconnected.', true);
  }
  async function connect() {
    if (disposed || !available || !constructors) return;
    stop();
    const current = generation, controller = new AbortController();
    const entry = active = { controller };
    show('Connecting to the terminal…');
    try {
      const { socket } = await services.transport.socket('terminal', options.host, controller.signal);
      if (disposed || generation !== current) { socket.close(); return; }
      entry.socket = socket;
      const [{ Terminal }, { FitAddon }] = constructors;
      const font = (options.getComputedStyle || globalThis.getComputedStyle)(display).fontFamily;
      const terminal = entry.terminal = new Terminal({ scrollback: 5000, theme: theme(), allowProposedApi: false, fontSize: 13, ...(font ? { fontFamily: font } : {}) });
      const fit = new FitAddon();
      terminal.loadAddon(fit);
      terminal.open(display);
      const send = (data) => { if (active === entry && socket.readyState === 1) socket.send(data); };
      const resize = () => {
        if (!display.clientWidth || !display.clientHeight) return;
        fit.fit();
        send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
      };
      const opened = () => { card.hidden = true; resize(); };
      const received = (event) => {
        if (active !== entry || !(event.data instanceof ArrayBuffer)) return;
        const bytes = new Uint8Array(event.data);
        terminal.write(bytes, () => send(JSON.stringify({ type: 'ack', bytes: bytes.byteLength })));
      };
      const closed = (event) => { if (active === entry) disconnected(event.reason); };
      const input = terminal.onData((text) => send(new TextEncoder().encode(text)));
      const binary = terminal.onBinary((text) => send(Uint8Array.from(text, (c) => c.charCodeAt(0))));
      socket.addEventListener('open', opened);
      socket.addEventListener('message', received);
      socket.addEventListener('close', closed);
      entry.cleanup = () => {
        input.dispose();
        binary.dispose();
        socket.removeEventListener('open', opened);
        socket.removeEventListener('message', received);
        socket.removeEventListener('close', closed);
      };
      entry.observer = new ResizeObserver(resize);
      entry.observer.observe(display);
      if (socket.readyState === 1) opened();
    } catch (error) {
      if (!disposed && generation === current) disconnected(error.message);
    }
  }
  reconnect.addEventListener('click', connect);
  const offTheme = services.theme.subscribe(() => {
    if (active?.terminal) active.terminal.options.theme = theme();
  });
  const offStatus = services.state(options.status || `/api/state/host-${options.host}`, (snapshot) => {
    const wasAvailable = available;
    available = Boolean(snapshot.value?.terminal);
    if (!available) {
      stop();
      const state = snapshot.value?.state;
      if (!missing) show(state === 'stopped' ? `${options.host} has stopped.` : `${options.host} is booting. The terminal opens when SSH is up.`);
    } else if (!wasAvailable) void connect();
  }, (error) => {
    available = false;
    stop();
    show(`Terminal status unavailable: ${error.message}. Reload the demo to retry.`);
  });
  const load = options.load || (() => Promise.all([
    import('/vendor/xterm/lib/xterm.mjs').catch(() => { throw new Error('xterm.js'); }),
    import('/vendor/addon-fit/lib/addon-fit.mjs').catch(() => { throw new Error('The xterm.js fit addon'); }),
  ]));
  void load().then((modules) => {
    if (disposed) return;
    constructors = modules;
    void connect();
  }).catch((error) => {
    if (disposed) return;
    missing = true;
    show(`${error.message} is not in this build. Run \`cargo xtask demo assets\`, then rebuild.`);
  });
  return () => {
    if (disposed) return;
    disposed = true;
    offStatus();
    offTheme();
    stop();
    reconnect.removeEventListener('click', connect);
    root.replaceChildren();
    root.classList.remove('console-panel');
  };
}
