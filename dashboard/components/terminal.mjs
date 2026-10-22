// mount(root, services, options) -> dispose; shared services are described in README.md.
// A shell on the host through ghostty-web. Output is acknowledged after the terminal
// has written it, so the page server stops reading when the browser lags.
// With options.interactive the text starts large and options.controls gets
// A− and A+ buttons; the size is kept for the next visit.
import { mountConsole } from './console.mjs';
import { scoped, listen } from '../dom.mjs';

const SIZE_KEY = 'fictionet-terminal-size';

export function applyTheme(terminal, colors) {
  const color = (value) => value.startsWith('#') ? value : '#' + value.match(/\d+/g).slice(0, 3).map((n) => Number(n).toString(16).padStart(2, '0')).join('');
  terminal.renderer.setTheme(colors);
  terminal.write(`\x1b]10;${color(colors.foreground)}\x1b\\\x1b]11;${color(colors.background)}\x1b\\`);
  terminal.renderer.render(terminal.wasmTerm, true, terminal.getViewportY(), terminal);
}

export function mount(root, services, options) {
  let active, focus = options.focus, fontSize = 13;
  const sizing = [];
  if (options.interactive) {
    fontSize = 18;
    try { const saved = Number(localStorage.getItem(SIZE_KEY)); if (saved >= 10 && saved <= 36) fontSize = saved; } catch { /* The size still lasts for this page. */ }
    if (options.controls) {
      const { el } = scoped(root);
      for (const [text, label, step] of [['A−', 'Smaller text', -2], ['A+', 'Larger text', 2]]) {
        const button = el('button', { type: 'button', class: 'text-size', text, 'aria-label': label }, options.controls);
        sizing.push(listen(button, 'click', () => {
          fontSize = Math.max(10, Math.min(36, fontSize + step));
          try { localStorage.setItem(SIZE_KEY, String(fontSize)); } catch { /* Storage may be disabled. */ }
          if (active?.terminal) { active.terminal.options.fontSize = fontSize; active.resize?.(); }
        }));
      }
    }
  }
  const theme = (display) => {
    const computed = getComputedStyle(display);
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
      const { Terminal, FitAddon } = panel.library;
      const font = getComputedStyle(panel.display).fontFamily;
      const terminal = entry.terminal = new Terminal({ scrollback: 5000, theme: theme(panel.display), fontSize, ...(font ? { fontFamily: font } : {}) });
      const fit = new FitAddon();
      terminal.loadAddon(fit);
      const focused = panel.display.ownerDocument.activeElement;
      terminal.open(panel.display);
      if (!focus) { terminal.blur(); focused?.focus(); }
      panel.display.terminal = terminal;
      const send = (data) => { if (active === entry && socket.readyState === 1) socket.send(data); };
      const resize = () => {
        if (!panel.display.clientWidth || !panel.display.clientHeight) return;
        const size = fit.proposeDimensions();
        if (size && (size.cols !== terminal.cols || size.rows !== terminal.rows)) terminal.resize(size.cols, size.rows);
        send(JSON.stringify({ type: 'resize', cols: terminal.cols, rows: terminal.rows }));
      };
      entry.resize = resize;
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
      socket.addEventListener('open', opened);
      socket.addEventListener('message', received);
      socket.addEventListener('close', closed);
      entry.cleanup = () => {
        input.dispose();
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
    if (old?.terminal) delete panel.display.terminal;
    old?.terminal?.dispose();
  }
  const { panel, dispose } = mountConsole(root, services, options, {
    kind: 'terminal', display: 'terminal-display', retry: 'Reconnect', open, close,
    unavailable: () => { focus = false; },
    waiting: (state) => (state === 'network_up'
      ? `${options.host} is on the network. The terminal opens when SSH is up.`
      : `${options.host} is booting. The terminal opens when SSH is up.`),
    load: async () => {
      const ghostty = await services.importModule('/vendor/ghostty-web/dist/ghostty-web.js').catch(() => { throw new Error('ghostty-web'); });
      await ghostty.init();
      return ghostty;
    },
  });
  const offTheme = services.theme.subscribe(() => {
    if (active?.terminal) {
      // This release exposes the renderer; changing options.theme alone does
      // not repaint an open terminal.
      applyTheme(active.terminal, theme(panel.display));
    }
  });
  return () => {
    if (!dispose()) return;
    offTheme();
    sizing.forEach((off) => off());
    if (options.interactive) options.controls?.replaceChildren();
  };
}
