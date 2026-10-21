const OUT = 'cubic-bezier(.2,.7,.3,1)';
const IN_OUT = 'cubic-bezier(.4,0,.2,1)';

export function createMotion(window) {
  const media = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  const running = new Set(), transient = new Set(), typing = new Map();
  const listeners = new Set();
  let reduced = !!media?.matches, suppressed = false, disposed = false;
  const notify = () => { for (const listener of listeners) listener(reduced || suppressed || !!window.document?.hidden); };
  const active = () => !reduced && !suppressed && !disposed && !!window.document && !window.document.hidden;
  function clear() {
    for (const stop of typing.values()) stop();
    typing.clear();
    for (const animation of running) animation.cancel();
    running.clear();
    for (const node of transient) node.remove();
    transient.clear();
  }
  const changed = () => {
    reduced = !!media.matches;
    if (reduced) clear();
    notify();
  };
  const visibility = () => { if (window.document.hidden) clear(); notify(); };
  media?.addEventListener('change', changed);
  window.document?.addEventListener('visibilitychange', visibility);
  function anim(node, keyframes, options) {
    if (!active() || !node?.animate) return { finished: Promise.resolve(), cancel() {} };
    return play(node, keyframes, options);
  }
  function play(node, keyframes, options) {
    const animation = node.animate(keyframes, { fill: 'backwards', ...options });
    running.add(animation);
    const done = () => { running.delete(animation); animation.cancel(); };
    animation.finished.then(done, done);
    return animation;
  }
  function removeAfter(node, animation) {
    transient.add(node);
    const remove = () => { node.remove(); transient.delete(node); };
    animation.finished.then(remove, remove);
  }
  function node(layer, tag, attributes) {
    const element = layer.ownerDocument.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
    element.setAttribute('data-transient', '');
    layer.append(element);
    return element;
  }
  function travel(layer, from, to, cls, ms = 300) {
    if (!active()) return;
    const dot = node(layer, 'circle', { class: `travel ${cls}`, cx: 0, cy: 0, r: 3.5 });
    const frames = from?.getPointAtLength ? Array.from({ length: 33 }, (_, i) => {
      const p = from.getPointAtLength(from.getTotalLength() * i / 32);
      return { transform: `translate(${p.x}px, ${p.y}px)` };
    }) : [from, to].map(([x, y]) => ({ transform: `translate(${x}px, ${y}px)` }));
    removeAfter(dot, anim(dot, frames, { duration: ms, easing: IN_OUT }));
  }
  function drawIn(path, ms = 240, delay = 0) {
    const length = path.getTotalLength?.() ?? Math.hypot(Number(path.getAttribute('x2')) - Number(path.getAttribute('x1')), Number(path.getAttribute('y2')) - Number(path.getAttribute('y1')));
    return anim(path, [{ strokeDasharray: `${length}`, strokeDashoffset: length }, { strokeDasharray: `${length}`, strokeDashoffset: 0 }], { duration: ms, delay, easing: IN_OUT });
  }
  function ring(layer, x, y, cls, size = 22, ms = 600, delay = 0) {
    const stationary = reduced && !suppressed && !disposed && !window.document?.hidden && cls === 'again' && !delay;
    if (!active() && !stationary) return;
    const circle = node(layer, 'circle', { class: `ring ${cls}`, cx: x, cy: y, r: size });
    if (stationary) {
      removeAfter(circle, play(circle, [{ opacity: .9 }, { opacity: 0 }], { duration: 150 }));
      return;
    }
    circle.style.transformOrigin = `${x}px ${y}px`;
    removeAfter(circle, anim(circle, [{ transform: 'scale(.25)', opacity: .9 }, { transform: 'scale(1)', opacity: 0 }], { duration: ms, delay, easing: OUT }));
  }
  function pulse(node) {
    return anim(node, [{ transform: 'scale(1)' }, { transform: 'scale(1.28)', offset: .45 }, { transform: 'scale(1)' }], { duration: 380, easing: 'cubic-bezier(.3,.7,.3,1.1)' });
  }
  function typeInto(textNode, text, ms = Math.min(900, text.length * 28)) {
    typing.get(textNode)?.();
    if (!active() || !window.requestAnimationFrame || !text.length) { textNode.textContent = text; return; }
    let frame, start;
    const stop = () => { window.cancelAnimationFrame(frame); textNode.textContent = text; typing.delete(textNode); };
    typing.set(textNode, stop);
    textNode.textContent = '';
    const tick = (now) => {
      start ??= now;
      const progress = Math.min(1, (now - start) / Math.min(ms, 900));
      textNode.textContent = text.slice(0, Math.floor(text.length * progress));
      if (progress < 1) frame = window.requestAnimationFrame(tick);
      else typing.delete(textNode);
    };
    frame = window.requestAnimationFrame(tick);
  }
  return {
    anim, travel, drawIn, ring, pulse, typeInto, removeAfter, clear,
    get reduced() { return reduced; },
    get active() { return active(); },
    set suppressed(value) { suppressed = value; if (value) clear(); notify(); },
    subscribe(listener) { listeners.add(listener); notify(); return () => listeners.delete(listener); },
    dispose() { disposed = true; clear(); listeners.clear(); media?.removeEventListener('change', changed); window.document?.removeEventListener('visibilitychange', visibility); },
  };
}
