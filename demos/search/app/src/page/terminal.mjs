// The caller owns socket setup and serves its own ghostty-web library.
// Acknowledgements are sent only after output has been written.
export function mount(root, { Terminal, FitAddon }, socket, options = {}) {
  const terminal = new Terminal({ scrollback: 5000, ...options });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open(root);
  socket.binaryType = 'arraybuffer';
  const send = (value) => { if (socket.readyState === 1) socket.send(value); };
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
  return { dispose, setInput(enabled) { terminal.options.disableStdin = !enabled; } };
}
