// The fixture's custom panel: one bar per host, its height the packets that
// host sent, from the world's own exchange table. It draws only when the
// state, the panel size or the theme changes.
import * as THREE from 'three';

export function mount(root, services, options) {
  const document = root.ownerDocument;
  const caption = document.createElement('p');
  const stage = document.createElement('div');
  caption.className = 'custom-caption';
  caption.textContent = 'Packets sent by each host. Bars share one scale.';
  stage.className = 'custom-stage';
  root.append(caption, stage);

  const scene = new THREE.Scene();
  // A low, distant camera: the bars read as heights, with a little depth.
  const camera = new THREE.PerspectiveCamera(22, 1, 0.1, 100);
  camera.position.set(2.5, 3.5, 16);
  camera.lookAt(0, 1.5, 0);
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(globalThis.devicePixelRatio || 1, 2));
  stage.append(renderer.domElement);
  const geometry = new THREE.BoxGeometry(1, 1, 1);
  const material = new THREE.MeshLambertMaterial();
  const baseline = new THREE.LineBasicMaterial();
  const sun = new THREE.DirectionalLight(0xffffff, 1.8);
  sun.position.set(3, 6, 4);
  scene.add(new THREE.AmbientLight(0xffffff, 1.6), sun);
  const floor = new THREE.LineSegments(new THREE.BufferGeometry(), baseline);
  scene.add(floor);
  let rows = [];
  const bars = [], labels = [];

  // Token colors, resolved for the scheme on screen.
  function token(name) {
    const probe = document.createElement('span');
    probe.style.color = `var(${name})`;
    stage.append(probe);
    const color = getComputedStyle(probe).color;
    probe.remove();
    return color;
  }
  function draw() {
    const width = stage.clientWidth, height = stage.clientHeight;
    if (!width || !height) return;
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.render(scene, camera);
    // Labels are text over the canvas: the host under its bar, the count on top.
    const place = (label, point) => {
      const at = point.clone().project(camera);
      label.style.left = `${((at.x + 1) / 2) * width}px`;
      label.style.top = `${((1 - at.y) / 2) * height}px`;
    };
    bars.forEach((bar, i) => {
      place(labels[i].count, new THREE.Vector3(bar.position.x, bar.scale.y + 0.35, 0));
      place(labels[i].host, new THREE.Vector3(bar.position.x, -0.5, 0.9));
    });
  }
  function paint() {
    material.color.set(token('--edge-live'));
    baseline.color.set(token('--line-strong'));
    draw();
  }
  function update() {
    while (bars.length > rows.length) {
      scene.remove(bars.pop());
      const label = labels.pop();
      label.count.remove();
      label.host.remove();
    }
    const largest = Math.max(1, ...rows.map((row) => row.packets));
    const span = (rows.length - 1) * 2.2;
    floor.geometry.dispose();
    floor.geometry = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(-span / 2 - 1.2, 0, 0), new THREE.Vector3(span / 2 + 1.2, 0, 0)]);
    rows.forEach((row, i) => {
      if (!bars[i]) {
        bars[i] = new THREE.Mesh(geometry, material);
        scene.add(bars[i]);
        const count = document.createElement('span'), host = document.createElement('span');
        count.className = 'custom-label value';
        host.className = 'custom-label';
        stage.append(count, host);
        labels[i] = { count, host };
      }
      const height = Math.max(0.02, (row.packets / largest) * 3);
      bars[i].scale.y = height;
      bars[i].position.set(i * 2.2 - span / 2, height / 2, 0);
      labels[i].count.textContent = String(row.packets);
      labels[i].host.textContent = row.host;
    });
    caption.textContent = rows.length ? 'Packets sent by each host. Bars share one scale.' : 'No exchanges yet.';
    draw();
  }

  const stopTheme = services.theme.subscribe(paint);
  const resize = new ResizeObserver(draw);
  resize.observe(stage);
  const stopState = services.state(options.state, ({ value }) => {
    rows = value || [];
    update();
  }, (error) => { caption.textContent = `The exchange table is unavailable: ${error.message}`; });

  return () => {
    stopState();
    stopTheme();
    resize.disconnect();
    floor.geometry.dispose();
    geometry.dispose();
    material.dispose();
    baseline.dispose();
    renderer.dispose();
    renderer.forceContextLoss();
    root.replaceChildren();
  };
}
