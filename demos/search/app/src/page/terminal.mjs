// The caller owns socket setup and serves its own ghostty-web library.
// Acknowledgements are sent only after output has been written.
export function mount(root, { Terminal, FitAddon }, socket, options = {}) {
  const terminal = new Terminal({ scrollback: 5000, ...options });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open(root);
  socket.binaryType = 'arraybuffer';
  const send = (value) => { if (socket.readyState === 1) socket.send(value); };
  let wheelPixels = 0;
  terminal.attachCustomWheelEventHandler((event) => {
    const canvas = root.querySelector('canvas');
    if (!canvas || !event.deltaY) return true;
    const bounds = canvas.getBoundingClientRect();
    const cellHeight = bounds.height / terminal.rows;
    const pixels = event.deltaY * (event.deltaMode === 1 ? cellHeight : event.deltaMode === 2 ? bounds.height : 1);
    const tracking = terminal.hasMouseTracking();
    if (tracking && !event.shiftKey) {
      if (Math.sign(wheelPixels) !== Math.sign(pixels)) wheelPixels = 0;
      wheelPixels += pixels;
      const lines = Math.min(terminal.rows, Math.trunc(Math.abs(wheelPixels) / cellHeight));
      if (!lines) return true;
      wheelPixels %= cellHeight;
      const column = Math.max(1, Math.min(terminal.cols, Math.floor((event.clientX - bounds.left) * terminal.cols / bounds.width) + 1));
      const row = Math.max(1, Math.min(terminal.rows, Math.floor((event.clientY - bounds.top) / cellHeight) + 1));
      const button = (pixels < 0 ? 64 : 65) + (event.altKey ? 8 : 0) + (event.ctrlKey ? 16 : 0);
      send(new TextEncoder().encode(`\x1b[<${button};${column};${row}M`.repeat(lines)));
    } else {
      wheelPixels = 0;
      terminal.scrollLines(pixels / cellHeight);
    }
    return true;
  });
  const input = terminal.onData((text) => send(new TextEncoder().encode(text)));
  const resize = () => {
    if (!root.clientWidth || !root.clientHeight) return;
    const size = fit.proposeDimensions();
    if (!size) return;
    terminal.resize(size.cols, size.rows);
    send(JSON.stringify({ type: 'resize', cols: size.cols, rows: size.rows }));
  };
  const received = (event) => {
    if (!(event.data instanceof ArrayBuffer)) return;
    const bytes = new Uint8Array(event.data);
    terminal.write(bytes, () => send(JSON.stringify({ type: 'ack', bytes: bytes.byteLength })));
  };
  const observer = new ResizeObserver(resize);
  observer.observe(root);
  socket.addEventListener('open', resize);
  socket.addEventListener('message', received);
  if (socket.readyState === 1) resize();
  const dispose = () => {
    observer.disconnect();
    input.dispose();
    socket.removeEventListener('open', resize);
    socket.removeEventListener('message', received);
    terminal.dispose();
  };
  return { dispose, setFontSize(fontSize) { terminal.options.fontSize = fontSize; resize(); } };
}
