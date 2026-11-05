// The caller owns socket setup and serves its own ghostty-web library.
// Acknowledgements are sent only after output has been written.
export function mount(root, { Terminal, FitAddon }, socket, options = {}) {
  const terminal = new Terminal({ scrollback: 5000, ...options });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open(root);
  socket.binaryType = 'arraybuffer';
  const send = (value) => { if (socket.readyState === 1) socket.send(value); };
  const pending = [];
  const input = terminal.onData((text) => {
    const bytes = new TextEncoder().encode(text);
    if (socket.readyState === 0) pending.push(bytes);
    else send(bytes);
  });
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
  const opened = () => {
    resize();
    for (const bytes of pending.splice(0)) send(bytes);
  };
  socket.addEventListener('open', opened);
  socket.addEventListener('message', received);
  if (socket.readyState === 1) resize();
  const dispose = () => {
    observer.disconnect();
    input.dispose();
    socket.removeEventListener('open', opened);
    socket.removeEventListener('message', received);
    pending.length = 0;
    terminal.dispose();
  };
  return { dispose, setFontSize(fontSize) { terminal.options.fontSize = fontSize; resize(); } };
}
