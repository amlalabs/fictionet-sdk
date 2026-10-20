// mount(root, services, options) -> dispose; shared services are described in README.md.
// A shell on the host through xterm.js. Output is acknowledged after xterm
// has written it, so the page server stops reading when the browser lags.
import { mountConsole } from './console.mjs';

export function mount(root, services, options) {
  const css = root.ownerDocument.createElement('link');
  css.rel = 'stylesheet';
  css.href = '/vendor/xterm/css/xterm.css';
  root.append(css);
  let active, focus = options.focus;
  const ResizeObserver = options.ResizeObserver || globalThis.ResizeObserver;
  const style = (element) => (options.getComputedStyle || globalThis.getComputedStyle)(element);
  const theme = (display) => {
    const computed = style(display);
    return { background: computed.backgroundColor, foreground: computed.color, cursor: computed.color };
  };
  function disconnected(panel, reason) {
    focus = false;
    panel.stop();
    if (panel.disposed || !panel.available || panel.ended()) return;
    panel.show(reason ? `Disconnected: ${reason}.` : 'Disconnected.', true);
  }
  async function open(panel) {
    const current = panel.generation, controller = new AbortController();
    const entry = active = { controller };
    panel.show('Connecting to the terminal…');
    try {
      const { socket } = await services.transport.socket('terminal', options.host, controller.signal);
      if (panel.disposed || panel.generation !== current) { socket.close(); return; }
      entry.socket = socket;
      const [{ Terminal }, { FitAddon }] = panel.library;
      const font = style(panel.display).fontFamily;
      const terminal = entry.terminal = new Terminal({ scrollback: 5000, theme: theme(panel.display), allowProposedApi: false, fontSize: 13, ...(font ? { fontFamily: font } : {}) });
      const fit = new FitAddon();
      terminal.loadAddon(fit);
      terminal.open(panel.display);
      const send = (data) => { if (active === entry && socket.readyState === 1) socket.send(data); };
      const resize = () => {
        if (!panel.display.clientWidth || !panel.display.clientHeight) return;
        fit.fit();
        send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
      };
      const opened = () => {
        panel.hide();
        resize();
        if (focus) { focus = false; terminal.focus(); }
      };
      const received = (event) => {
        if (active !== entry || !(event.data instanceof ArrayBuffer)) return;
        const bytes = new Uint8Array(event.data);
        terminal.write(bytes, () => send(JSON.stringify({ type: 'ack', bytes: bytes.byteLength })));
      };
      const closed = (event) => { if (active === entry) disconnected(panel, event.reason); };
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
      entry.observer.observe(panel.display);
      if (socket.readyState === 1) opened();
    } catch (error) {
      if (!panel.disposed && panel.generation === current) disconnected(panel, error.message);
    }
  }
  function close() {
    const old = active;
    active = null;
    old?.cleanup?.();
    old?.controller.abort();
    old?.socket?.close();
    old?.observer?.disconnect();
    old?.terminal?.dispose();
  }
  const { panel, dispose } = mountConsole(root, services, options, {
    kind: 'terminal', display: 'terminal-display', retry: 'Reconnect', open, close,
    unavailable: () => { focus = false; },
    waiting: (state) => (state === 'network_up'
      ? `${options.host} is on the network. The terminal opens when SSH is up.`
      : `${options.host} is booting. The terminal opens when SSH is up.`),
    load: options.load || (() => Promise.all([
      import('/vendor/xterm/lib/xterm.mjs').catch(() => { throw new Error('xterm.js'); }),
      import('/vendor/addon-fit/lib/addon-fit.mjs').catch(() => { throw new Error('The xterm.js fit addon'); }),
    ])),
  });
  const offTheme = services.theme.subscribe(() => {
    if (active?.terminal) active.terminal.options.theme = theme(panel.display);
  });
  return () => {
    if (!dispose()) return;
    offTheme();
  };
}
