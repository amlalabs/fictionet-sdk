// One theme choice for the page and its panels; storage is optional.
export function createTheme(button, {
  document = globalThis.document, location = globalThis.location,
  matchMedia = globalThis.matchMedia, storage,
} = {}) {
  const system = matchMedia('(prefers-color-scheme: dark)');
  const listeners = new Set();
  let choice;
  try {
    storage ??= globalThis.localStorage;
    choice = storage.getItem('fictionet-theme');
  } catch { /* The choice still lasts for this page. */ }
  choice = new URLSearchParams(location.search).get('theme') || choice;
  if (!['light', 'dark'].includes(choice)) choice = null;
  const current = () => choice || (system.matches ? 'dark' : 'light');
  function apply() {
    if (choice) document.documentElement.dataset.theme = choice;
    else delete document.documentElement.dataset.theme;
    button?.setAttribute('aria-label', `Switch to ${current() === 'dark' ? 'light' : 'dark'} theme`);
    for (const listener of listeners) listener(current());
  }
  function toggle() {
    choice = current() === 'dark' ? 'light' : 'dark';
    try { storage?.setItem('fictionet-theme', choice); } catch { /* Storage may be disabled. */ }
    apply();
  }
  apply();
  system.addEventListener('change', apply);
  button?.addEventListener('click', toggle);
  return {
    current,
    subscribe(listener) { listeners.add(listener); listener(current()); return () => listeners.delete(listener); },
    dispose() {
      system.removeEventListener('change', apply);
      button?.removeEventListener('click', toggle);
      listeners.clear();
    },
  };
}
