// noVNC handles the screen protocol.
export function mount(root, RFB, socket) {
  const screen = new RFB(root, socket);
  screen.scaleViewport = true;
  return { dispose() { screen.disconnect(); } };
}
