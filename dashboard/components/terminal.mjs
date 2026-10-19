// mount(root, services, options) -> dispose; shared services are described in README.md.
export function mount(root, services, options) {
  const document = root.ownerDocument;
  const message = document.createElement('p'), reconnect = document.createElement('button');
  const display = document.createElement('div'), css = document.createElement('link');
  css.rel = 'stylesheet';
  css.href = '/vendor/xterm/css/xterm.css';
  display.className = 'terminal-display';
  root.classList.add('console-panel');
  message.textContent = 'Loading terminal…';
  message.setAttribute('role', 'status');
  reconnect.textContent = 'Reconnect';
  reconnect.hidden = true;
  root.append(css, message, reconnect, display);
  let disposed = false, available = false, missing = false, constructors, active, generation = 0;
  const ResizeObserver = options.ResizeObserver || globalThis.ResizeObserver;
  const theme = () => {
    const style = (options.getComputedStyle || globalThis.getComputedStyle)(display);
    return { background: style.backgroundColor, foreground: style.color, cursor: style.color };
  };
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
    message.hidden = false;
    message.textContent = reason ? `Disconnected. ${reason}` : 'Disconnected. Reconnect';
    reconnect.hidden = false;
  }
  async function connect() {
    if (disposed || !available || !constructors) return;
    stop();
    const current = generation, controller = new AbortController();
    const entry = active = { controller };
    message.hidden = false;
    message.textContent = 'Connecting terminal…';
    reconnect.hidden = true;
    try {
      const { socket } = await services.transport.socket('terminal', options.host, controller.signal);
      if (disposed || generation !== current) { socket.close(); return; }
      entry.socket = socket;
      const [{ Terminal }, { FitAddon }] = constructors;
      const terminal = entry.terminal = new Terminal({ scrollback: 5000, theme: theme(), allowProposedApi: false });
      const fit = new FitAddon();
      terminal.loadAddon(fit);
      terminal.open(display);
      const send = (data) => { if (active === entry && socket.readyState === 1) socket.send(data); };
      const resize = () => {
        if (!display.clientWidth || !display.clientHeight) return;
        fit.fit();
        send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
      };
      const opened = () => { message.hidden = true; resize(); };
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
      if (!missing) {
        message.hidden = false;
        message.textContent = `${options.host} is ${snapshot.value?.state === 'stopped' ? 'stopped' : 'booting'}. The terminal opens when SSH is up.`;
      }
      reconnect.hidden = true;
    } else if (!wasAvailable) void connect();
  }, (error) => {
    available = false;
    stop();
    message.hidden = false;
    reconnect.hidden = true;
    message.textContent = `Terminal status unavailable: ${error.message}. Reload the demo to retry.`;
  });
  const load = options.load || (() => Promise.all([
    import('/vendor/xterm/lib/xterm.mjs').catch(() => { throw new Error('xterm.js'); }),
    import('/vendor/addon-fit/lib/addon-fit.mjs').catch(() => { throw new Error('The xterm fit addon'); }),
  ]));
  void load().then((modules) => {
    if (disposed) return;
    constructors = modules;
    void connect();
  }).catch((error) => {
    if (disposed) return;
    missing = true;
    message.textContent = `${error.message} is not in this build. Run \`cargo xtask demo assets\`, then rebuild.`;
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
