// The app chooses input policy; noVNC handles the screen protocol.
export function mount(root, RFB, socket, input = false) {
  const screen = new RFB(root, socket);
  screen.scaleViewport = true;
  screen.viewOnly = !input;
  return { dispose() { screen.disconnect(); }, setInput(enabled) { screen.viewOnly = !enabled; } };
}
