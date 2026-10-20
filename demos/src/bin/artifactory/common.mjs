// Helpers the Artifactory panels share. World strings (paths, hosts, folder
// names, usernames) are only ever set as text.

// The page's color groups for request classifications, as the world's facts
// assign them. They are display groups, not scores.
export const FAMILIES = [
  ['read', 'Normal reads'],
  ['lookalike', 'Lookalike'],
  ['upstream', 'Upstream attempts'],
  ['write', 'Writes'],
  ['left', 'Left the world'],
];

const MECHANISMS = { basic: 'Basic', bearer: 'Bearer', api_key: 'API key', userinfo: 'URI user info', other: 'Other' };

// A credential attempt as the world keeps it: mechanism, user and the
// secret's length. Nothing else in the value is read.
export function credential(value) {
  if (!value) return '';
  const mechanism = value.scheme === 'other' && value.scheme_name ? value.scheme_name : MECHANISMS[value.scheme] || 'Other';
  const user = value.user == null ? 'no user' : `user ${value.user}`;
  const length = Number(value.secret_len) || 0;
  return `${mechanism}, ${user}, ${length}-byte secret`;
}

export function words(value) { return String(value ?? '').replaceAll('_', ' '); }

// The common start and end of two names and what differs between them.
export function nameDiff(a, b) {
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let end = 0;
  while (end < a.length - start && end < b.length - start && a[a.length - 1 - end] === b[b.length - 1 - end]) end++;
  return { prefix: a.slice(0, start), a: a.slice(start, a.length - end), b: b.slice(start, b.length - end), suffix: a.slice(a.length - end) };
}

// Creates elements under one document and keeps the listeners it adds, so
// dispose can remove them.
export function builder(root) {
  const document = root.ownerDocument;
  const cleanups = [];
  function el(tag, cls, text, parent) {
    const node = document.createElement(tag);
    if (cls) node.setAttribute('class', cls);
    if (text !== undefined && text !== null) node.textContent = text;
    parent?.append(node);
    return node;
  }
  function on(node, name, action) {
    node.addEventListener(name, action);
    cleanups.push(() => node.removeEventListener(name, action));
    return node;
  }
  function button(parent, cls, text, action) {
    const node = el('button', cls, text, parent);
    node.setAttribute('type', 'button');
    return on(node, 'click', action);
  }
  function stylesheet() {
    const link = el('link', '', undefined, root);
    link.setAttribute('rel', 'stylesheet');
    link.setAttribute('href', '/assets/artifactory/artifactory.css');
  }
  // Sets text only when it changed, so live counts never reflow needlessly.
  function set(node, text) { if (node.textContent !== text) node.textContent = text; }
  return { el, on, button, stylesheet, set, release: () => { cleanups.splice(0).forEach((off) => off()); } };
}

// Subscribes to several state topics and calls back with the latest value of
// each once any of them changes. Returns one unsubscribe function.
export function topics(services, paths, update, failure) {
  const values = Object.fromEntries(Object.keys(paths).map((name) => [name, null]));
  const statuses = {};
  let stopped = false;
  const stops = Object.entries(paths).map(([name, path]) => services.state(path, (snapshot) => {
    if (stopped) return;
    values[name] = snapshot.value ?? null;
    statuses[name] = snapshot.status || {};
    update(values, statuses);
  }, (error) => { if (!stopped) failure(name, error); }));
  return () => { stopped = true; stops.forEach((stop) => stop()); };
}

// The story steps whose pip install exited 0. Only these install packages.
export function installSteps(story) {
  return new Set((story || []).filter((step) => step.state === 'done' && step.exit === 0 && /^pip install\b/.test(step.command)).map((step) => step.title));
}

// Whether a request row shows the world sending a whole wheel.
export function servedWheel(row) {
  return row.method === 'GET' && row.classification === 'file' && row.outcome?.kind === 'served' && row.outcome?.complete === true && Boolean(row.package?.filename);
}
