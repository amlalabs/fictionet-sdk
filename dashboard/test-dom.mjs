// Minimal DOM for component lifecycle and rendering tests. Not served.
export class Element extends EventTarget {
  constructor(tag) {
    super();
    this.tag = tag;
    this.attributes = new Map();
    this.style = { setProperty(name, value) { this[name] = value; } };
    this.listeners = new Map();
    this.children = [];
    this.dataset = {};
    this.hidden = false;
    // A real button or input starts enabled.
    this.disabled = false;
    this.value = '';
    this.scrollHeight = this.scrollTop = this.clientHeight = 0;
    const classes = new Set();
    this.classList = {
      add: (name) => classes.add(name),
      remove: (name) => classes.delete(name),
      contains: (name) => classes.has(name),
      toggle: (name, on) => on ? classes.add(name) : classes.delete(name),
    };
  }
  addEventListener(name, callback, options) {
    super.addEventListener(name, callback, options);
    if (!this.listeners.has(name)) this.listeners.set(name, new Set());
    this.listeners.get(name).add(callback);
  }
  removeEventListener(name, callback, options) {
    super.removeEventListener(name, callback, options);
    this.listeners.get(name)?.delete(callback);
  }
  get listenerCount() { return [...this.listeners.values()].reduce((n, set) => n + set.size, 0); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === 'id') this.id = String(value);
    if (name === 'class') String(value).split(/\s+/).forEach((c) => this.classList.add(c));
    if (name.startsWith('data-')) this.dataset[name.slice(5)] = String(value);
  }
  appendChild(child) {
    if (child.tag === 'fragment') [...child.children].forEach((c) => this.appendChild(c));
    else {
      if (child.parent) child.remove();
      this.children.push(child);
      if (typeof child !== 'string') child.parent = this;
    }
  }
  getContext() { return { measureText: (text) => ({ width: String(text).length * 7 }) }; }
  getBoundingClientRect() { return { left: 0, top: 0, width: 800, height: 600 }; }
  matches(selector) { return selector !== ':hover' && this.tag === selector; }
  contains(node) { return this === node || this.children.some((child) => typeof child !== 'string' && child.contains(node)); }
  focus() { this.ownerDocument.activeElement = this; }
  scrollIntoView() {}
  get firstChild() { return this.children[0]; }
  get parentNode() { return this.parent || null; }
  // As in a browser, inserting a node that has a parent moves it.
  insertBefore(child, before) {
    if (child.parent) child.remove();
    const index = before ? this.children.indexOf(before) : this.children.length;
    this.children.splice(index, 0, child);
    child.parent = this;
    return child;
  }
  remove() {
    if (!this.parent) return;
    this.parent.children.splice(this.parent.children.indexOf(this), 1);
    this.parent = null;
  }
  append(...children) { children.forEach((child) => this.appendChild(child)); }
  replaceChildren(...children) {
    this.children = [];
    this.append(...children);
  }
  set textContent(text) { this.children = [String(text)]; }
  get textContent() { return this.children.map((c) => typeof c === 'string' ? c : c.textContent).join(''); }
  querySelectorAll(selector) {
    return this.children.flatMap((child) => {
      if (typeof child === 'string') return [];
      const [tag, cls] = selector.split('.');
      const match = selector.startsWith('#') ? child.id === selector.slice(1)
        : (!tag || tag === child.tag) && (!cls || child.classList.contains(cls));
      return [...(match ? [child] : []), ...child.querySelectorAll(selector)];
    });
  }
  click() { this.dispatchEvent(new Event('click')); }
}


export function createDocument() {
  const document = Object.assign(new Element('document'), {
    activeElement: null,
    createElement(tag) { const element = new Element(tag); element.ownerDocument = document; return element; },
    createElementNS(_, tag) { return this.createElement(tag); },
    createDocumentFragment() { return this.createElement('fragment'); },
    getElementById(id) { return this.documentElement.querySelector(`#${id}`); },
  });
  document.documentElement = document.createElement('html');
  document.body = document.createElement('body');
  document.documentElement.append(document.body);
  document.append(document.documentElement);
  return document;
}

// Replaces the global setTimeout and clearTimeout until test `t` ends, and
// returns its pending timers by id, each `{ callback, delay }`. Calls for
// the same test share the map.
const timersOf = new WeakMap();
export function fakeTimers(t) {
  if (timersOf.has(t)) return timersOf.get(t);
  const timers = new Map();
  timersOf.set(t, timers);
  t.mock.method(globalThis, 'setTimeout', (callback, delay) => { const id = Symbol(); timers.set(id, { callback, delay }); return id; });
  t.mock.method(globalThis, 'clearTimeout', (id) => { timers.delete(id); });
  return timers;
}

// Counts the live subscriptions to `store`, such as the graph model or the
// selection, by wrapping its `subscribe`, or the method named `method` that
// returns an unsubscribe function, such as `onMoment`. A panel outlived by a
// store must let go of it when disposed: returns a function that gives the
// count.
export function liveSubscriptions(store, method = 'subscribe') {
  const live = new Set(), subscribe = store[method];
  store[method] = (...args) => {
    const token = {}, off = subscribe(...args);
    live.add(token);
    return () => { live.delete(token); off(); };
  };
  return () => live.size;
}
