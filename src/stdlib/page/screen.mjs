// Pass the noVNC RFB class and an open WebSocket. The page owns input policy.
export function mount(root, RFB, socket, options = {}) {
  const screen = new RFB(root, socket);
  screen.scaleViewport = true;
  screen.viewOnly = true;
  Object.assign(screen, options);
  return () => screen.disconnect();
}
