// Bars show the real packet counts. No frame loop runs between updates.
export function mount(root, services, options) {
  const document = root.ownerDocument;
  const message = document.createElement('p');
  message.textContent = 'Loading traffic…';
  root.append(message);
  let disposed = false, stopState, stopTheme, resize, renderer, geometry, material;
  const bars = [], labels = [];
  async function load() {
    let three;
    try { three = await import('three'); }
    catch {
      if (!disposed) message.textContent = 'three.js is not in this build. Run `cargo xtask demo assets`, then rebuild.';
      return;
    }
    if (disposed) return;
    try {
      const scene = new three.Scene();
      const camera = new three.PerspectiveCamera(40, 1, 0.1, 100);
      camera.position.set(5, 5, 8); camera.lookAt(0, 1, 0);
      renderer = new three.WebGLRenderer({ antialias: true });
      renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
      root.append(renderer.domElement);
      geometry = new three.BoxGeometry(1, 1, 1);
      material = new three.MeshBasicMaterial();
      const draw = () => {
        const width = root.clientWidth, height = Math.max(100, root.clientHeight - message.offsetHeight - 32);
        renderer.setSize(width, height, false);
        renderer.domElement.style.width = '100%';
        renderer.domElement.style.height = `${height}px`;
        camera.aspect = width / height; camera.updateProjectionMatrix();
        renderer.render(scene, camera);
      };
      const palette = () => {
        const style = getComputedStyle(root);
        // Computed colors resolve the shared light and dark tokens.
        const probe = document.createElement('span');
        probe.style.color = 'var(--accent)'; root.append(probe);
        material.color.set(getComputedStyle(probe).color); probe.remove();
        renderer.setClearColor(style.backgroundColor === 'rgba(0, 0, 0, 0)' ? getComputedStyle(document.body).backgroundColor : style.backgroundColor);
        draw();
      };
      stopTheme = services.theme.subscribe(palette);
      resize = new ResizeObserver(draw); resize.observe(root);
      stopState = services.state(options.state, ({ value }) => {
        const rows = value || [];
        while (bars.length > rows.length) { scene.remove(bars.pop()); labels.pop().remove(); }
        const largest = Math.max(1, ...rows.map((row) => row.packets));
        rows.forEach((row, index) => {
          if (!bars[index]) {
            bars[index] = new three.Mesh(geometry, material); scene.add(bars[index]);
            labels[index] = document.createElement('span'); root.append(labels[index]);
          }
          const height = row.packets / largest * 3;
          bars[index].scale.y = height; bars[index].position.set((index - (rows.length - 1) / 2) * 2, height / 2, 0);
          labels[index].textContent = `${row.host}: ${row.packets} packets sent. `;
        });
        message.textContent = rows.length ? 'Packets sent by host. Heights share the same scale.' : 'No exchanges yet.';
        draw();
      }, (error) => { message.textContent = `Traffic state unavailable: ${error.message}`; });
    } catch (error) {
      if (!disposed) message.textContent = `Could not draw traffic: ${error.message}`;
    }
  }
  void load();
  return () => {
    disposed = true; stopState?.(); stopTheme?.(); resize?.disconnect();
    geometry?.dispose(); material?.dispose(); renderer?.dispose(); renderer?.forceContextLoss(); root.replaceChildren();
  };
}
