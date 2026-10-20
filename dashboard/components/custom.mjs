// mount(root, services, options) returns dispose. Modules share the page services.
import { scoped } from '../dom.mjs';

export function mount(root, services, options) {
  const { el } = scoped(root);
  const status = el('p', { class: 'empty-note', role: 'status', text: 'Loading…' }, root);
  const content = el('div', { class: 'custom-content' }, root);
  let disposed = false, stop;
  async function load() {
    try {
      if (!/^\/panels\/[A-Za-z0-9_-]{1,128}\.mjs$/.test(options.module)) throw new Error('Invalid panel module path');
      let module;
      try {
        module = await (services.importModule ? services.importModule(options.module) : import(options.module));
      } catch (error) {
        if (services.stopped?.()) throw new Error('the run has stopped, so the panel can no longer be loaded');
        throw new Error(`${error.message}. A panel that imports three.js needs it in the build: run \`cargo xtask demo libraries\`, then rebuild`);
      }
      if (disposed) return;
      const mounted = await module.mount(content, services, options);
      if (typeof mounted !== 'function') throw new Error('The panel must return a dispose function');
      if (disposed) mounted();
      else { stop = mounted; status.remove(); }
    } catch (error) {
      if (!disposed) status.textContent = `Could not open ${options.title}: ${error.message}`;
    }
  }
  void load();
  return () => { disposed = true; stop?.(); root.replaceChildren(); };
}
