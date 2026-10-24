// noVNC handles the screen protocol.
export function mount(root, RFB, socket) {
  const screen = new RFB(root, socket);
  screen.scaleViewport = true;
  // The guest desktop takes the pane's size, so it fills the pane.
  screen.resizeSession = true;
  return { dispose() { screen.disconnect(); } };
}
