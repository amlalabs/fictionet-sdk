// Tests for packet history reloads with injected streams and detail requests.
// The Rust test `dashboard_js` runs them when node is installed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPackets } from './packets.mjs';
import { createTransport } from './transport.mjs';
import { $, el } from './dom.mjs';

class Element extends EventTarget {
  constructor(tag) {
    super();
    this.tag = tag;
    this.children = [];
    this.dataset = {};
    this.hidden = false;
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
  setAttribute(name, value) {
    if (name === 'class') String(value).split(/\s+/).forEach((c) => this.classList.add(c));
    if (name.startsWith('data-')) this.dataset[name.slice(5)] = String(value);
  }
  appendChild(child) {
    if (child.tag === 'fragment') this.children.push(...child.children);
    else this.children.push(child);
  }
  append(...children) { children.forEach((child) => this.appendChild(child)); }
  replaceChildren(...children) {
    this.children = [];
    this.append(...children);
  }
  set textContent(text) { this.children = [String(text)]; }
  get textContent() { return this.children.map((c) => typeof c === 'string' ? c : c.textContent).join(''); }
  querySelectorAll(selector) {
    assert.equal(selector, 'tr.on');
    return this.children.filter((c) => c.classList?.contains('on'));
  }
  click() { this.dispatchEvent(new Event('click')); }
}

function setup(t, links = ['a']) {
  const elements = new Map();
  const previousDocument = globalThis.document;
  t.after(() => {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
  });
  globalThis.document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, new Element('div'));
      return elements.get(id);
    },
    createElement: (tag) => new Element(tag),
    createDocumentFragment: () => new Element('fragment'),
  };
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const sources = [];
  class EventSource extends EventTarget {
    constructor(url) {
      super();
      this.url = url;
      sources.push(this);
    }
    emit(name, data) {
      const event = new Event(name);
      event.data = JSON.stringify(data);
      this.dispatchEvent(event);
    }
    close() { this.closed = true; }
  }
  const requests = [];
  const transport = createTransport({}, {
    EventSource,
    fetch: (url) => new Promise((resolve) => requests.push({ url, resolve })),
  });
  const view = createPackets({ $, el, ...transport, fmtCount: String, fit() {} });
  const open = () => view.openLinks('From', 'To', links.map((id) => ({ e: { id }, flip: false })));
  open();
  const source = sources[0];
  source.emit('open');
  return {
    view, source, sources, requests, open,
    flush() { now += 401; view.flush(); },
    rows: () => $('prows').children.filter((r) => !r.classList.contains('gap')),
    send(seq, { link = links[0], skipped = 2, ...rest } = {}) {
      source.emit('packet', { seq, link, skipped, t: seq, side: 0, tags: [], src: 'a', dst: 'b', proto: 'TCP', len: 40, info: `packet ${seq}`, ...rest });
    },
  };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));
const detail = (seq) => ({ seq, len: 40, t: seq, layers: [], buffers: [] });

test('repeated reconnects replace single-link rows and sampling totals before replay', async (t) => {
  const h = setup(t);
  for (let reconnect = 0; reconnect < 3; reconnect++) {
    h.send(1);
    h.send(2);
    await settle();
    h.flush();
    assert.deepEqual(h.rows().map((r) => r.dataset.seq), ['1', '2']);
    assert.equal($('sampled').textContent, 'Sampled: 4 packets not copied');
    h.send(3); // A packet waiting for the next animation frame.
    h.source.emit('error');
    assert.equal(h.rows().length, 2);
    h.source.emit('open');
    assert.equal(h.rows().length, 0);
    assert.match($('prows').textContent, /history reloaded/);
    assert.equal($('sampled').hidden, true);
    assert.equal($('sampled').textContent, '');
    h.flush();
    assert.equal(h.rows().length, 0);
  }
  // A new capture can restart at 1 with entirely different contents.
  h.send(1, { info: 'new capture', skipped: 0 });
  h.flush();
  assert.match(h.rows()[0].textContent, /new capture/);
  assert.equal($('sampled').hidden, true);
});

test('merged replay restarts display numbering and discards packets held for ordering', async (t) => {
  const h = setup(t, ['a', 'b']);
  for (let reconnect = 0; reconnect < 3; reconnect++) {
    h.send(9, { link: 'b', t: 2 });
    h.send(4, { link: 'a', t: 1 });
    await settle();
    h.flush();
    assert.deepEqual(h.rows().map((r) => [r.children[0].textContent, r.dataset.link, r.dataset.seq]), [['1', 'a', '4'], ['2', 'b', '9']]);
    assert.equal($('sampled').textContent, 'Sampled: 4 packets not copied');
    h.send(10, { link: 'b' });
    h.view.flush(); // Still within the merge hold window.
    assert.equal(h.rows().length, 2);
    h.source.emit('open');
    h.flush();
    assert.equal(h.rows().length, 0);
  }
});

test('paused reconnect clears both pending queues and stays paused until resumed', async (t) => {
  const h = setup(t);
  h.send(1);
  h.flush();
  h.send(2); // Pending before pausing.
  $('pause').click();
  h.send(3); // Held while paused.
  for (let reconnect = 0; reconnect < 3; reconnect++) {
    h.source.emit('open');
    h.send(1);
    await settle();
    h.flush();
    assert.equal(h.rows().length, 0);
    assert.equal($('pause').textContent, 'Resume');
    assert.equal($('sampled').hidden, true);
  }
  $('pause').click();
  h.flush();
  assert.deepEqual(h.rows().map((r) => r.dataset.seq), ['1']);
  assert.equal($('sampled').textContent, 'Sampled: 2 packets not copied');
});

test('reconnect clears detail and ignores responses from the previous history', async (t) => {
  const h = setup(t);
  h.send(1);
  h.flush();
  h.rows()[0].click();
  h.requests[0].resolve({ ok: true, json: async () => detail(1) });
  await settle();
  assert.match($('tree').textContent, /Packet 1/);
  assert.equal($('hex').hidden, false);

  for (const stage of ['fetch', 'json', 'missing']) {
    h.rows()[0].click();
    const request = h.requests.at(-1);
    let resolve;
    if (stage === 'json') {
      request.resolve({ ok: true, json: () => new Promise((done) => { resolve = done; }) });
      await settle();
    }
    h.source.emit('open');
    assert.equal($('hex').hidden, true);
    assert.equal($('hex-dump').textContent, '');
    assert.equal($('prows').querySelectorAll('tr.on').length, 0);
    h.send(1, { info: 'restarted' });
    h.flush();
    h.rows()[0].click();
    h.requests.at(-1).resolve({ ok: true, json: async () => detail(100) });
    await settle();
    if (stage === 'json') resolve(detail(1));
    else request.resolve({ ok: stage !== 'missing', json: async () => detail(1) });
    await settle();
    assert.match($('tree').textContent, /Packet 100/);
  }
});

test('a closed stream reopening cannot reset a different drawer', (t) => {
  const h = setup(t);
  h.open();
  assert.equal(h.source.closed, true);
  h.sources[1].emit('open');
  assert.doesNotMatch($('tree').textContent, /reloaded/);
  h.source.emit('open');
  assert.doesNotMatch($('tree').textContent, /reloaded/);
});
