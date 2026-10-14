// Tests for packet history and selection with injected streams and detail requests.
// The Rust test `dashboard_js` runs them when node is installed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createPackets } from './packets.mjs';
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
    if (child.tag === 'fragment') child.children.forEach((c) => this.appendChild(c));
    else {
      this.children.push(child);
      if (typeof child !== 'string') child.parent = this;
    }
  }
  get firstChild() { return this.children[0]; }
  remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); }
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

function setup(t, links = ['a'], maxRows = 3000) {
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
  const downloads = [];
  let downloadError;
  const transport = {
    packetStream(list, reconnected) {
      const source = new EventSource(`api/packets?link=${list}`);
      let opened = false;
      source.addEventListener('open', () => {
        if (opened) reconnected();
        opened = true;
      });
      return source;
    },
    packet: (p, signal) => new Promise((resolve, reject) => requests.push({ url: `api/packet?link=${p.link}&seq=${p.seq}`, signal, resolve, reject })),
    download: async (...args) => { downloads.push(args); if (downloadError) throw downloadError; },
  };
  const view = createPackets({ $, el, ...transport, fmtCount: String, fit() {}, maxRows });
  const open = () => view.openLinks('From', 'To', links.map((id) => ({ e: { id }, flip: false })));
  open();
  const source = sources[0];
  source.emit('open');
  return {
    view, source, sources, requests, downloads, open,
    failDownload(error) { downloadError = error; },
    flush() { now += 401; view.flush(); },
    rows: () => $('prows').children.filter((r) => !r.classList.contains('gap')),
    send(seq, { link = links[0], skipped = 2, ...rest } = {}) {
      source.emit('packet', { seq, link, skipped, t: seq, side: 0, tags: [], src: 'a', dst: 'b', proto: 'TCP', len: 40, info: `packet ${seq}`, ...rest });
    },
  };
}

const settle = () => new Promise((resolve) => setImmediate(resolve));
const detail = (seq) => ({ seq, len: 40, t: seq, layers: [], buffers: [{ name: 'packet', hex: '4142' }, { name: 'payload', hex: '43' }] });

test('capture eviction and subscriber overruns stay distinct from sampling and row identity', async (t) => {
  const h = setup(t);
  h.source.emit('packet_gap', { after: 1, next: 5, missed: 3 });
  h.send(5, { skipped: 2, evicted: 7 });
  h.send(6, { skipped: 0, evicted: 0 });
  h.flush();
  assert.match($('prows').textContent, /Packets 2–4 of link a are no longer kept/);
  assert.equal($('sampled').textContent, 'Sampled: 2 packets not copied · Capture: 7 copies evicted · Subscriber: 3 rows missed');
  const [first, second] = h.rows();
  assert.deepEqual(h.rows().map((r) => r.dataset.seq), ['5', '6']);
  assert.equal(first.classList.contains('after-gap'), true);
  assert.match(first.title, /2 packets before this one not copied/);
  assert.match(first.title, /7 captured copies before this one evicted before decoding/);
  assert.equal(second.classList.contains('after-gap'), false);
  first.click();
  assert.match(h.requests[0].url, /link=a&seq=5/);
  h.requests[0].resolve({ ok: true, json: async () => detail(5) });
  await settle();
  assert.match($('tree').textContent, /Packet 5/);
});

test('merged loss names its link and leaves display and detail numbering intact', (t) => {
  const h = setup(t, ['a', 'b']);
  h.source.emit('packet_gap', { link: 'b', after: 0, next: 9, missed: 8 });
  h.send(9, { link: 'b', t: 2, evicted: 3, skipped: 0 });
  h.send(4, { link: 'a', t: 1, evicted: 2, skipped: 0 });
  h.flush();
  assert.match($('prows').textContent, /Packets 1–8 of link b/);
  assert.deepEqual(h.rows().map((r) => [r.children[0].textContent, r.dataset.link, r.dataset.seq]), [['1', 'a', '4'], ['2', 'b', '9']]);
  assert.equal($('sampled').textContent, 'Capture: 5 copies evicted · Subscriber: 8 rows missed');
  for (const row of h.rows()) assert.equal(row.classList.contains('after-gap'), true);
});

for (const paused of [false, true]) {
  test(`subscriber gaps follow earlier packets while ${paused ? 'paused' : 'waiting to render'}`, (t) => {
    const h = setup(t);
    h.send(1, { skipped: 0 }); // Queued before any pause.
    if (paused) $('pause').click();
    h.send(2, { skipped: 0 });
    h.send(3, { skipped: 0 });
    h.source.emit('packet_gap', { after: 3, next: 10, missed: 6 });
    assert.equal($('sampled').textContent, 'Subscriber: 6 rows missed');
    h.send(10, { skipped: 0 });
    if (paused) $('pause').click();
    h.flush();
    assert.deepEqual($('prows').children.map((r) => r.dataset.seq), ['1', '2', '3', undefined, '10']);
    assert.equal($('prows').children[3].classList.contains('gap'), true);
  });
}

test('merged subscriber gaps follow earlier packets still held for ordering', (t) => {
  const h = setup(t, ['a', 'b']);
  h.send(1, { link: 'b', t: 2, skipped: 0 });
  h.send(1, { link: 'a', t: 1, skipped: 0 });
  h.view.flush(); // Both rows are still within the merge hold window.
  h.source.emit('packet_gap', { link: 'b', after: 1, next: 5, missed: 3 });
  assert.equal($('sampled').textContent, 'Subscriber: 3 rows missed');
  h.send(5, { link: 'b', t: 3, skipped: 0 });
  h.send(2, { link: 'a', t: 2, skipped: 0 });
  h.view.flush();
  h.flush();
  assert.deepEqual($('prows').children.map((r) => r.classList.contains('gap') ? 'gap' : `${r.dataset.link}:${r.dataset.seq}`), ['a:1', 'b:1', 'gap', 'a:2', 'b:5']);
  assert.deepEqual(h.rows().map((r) => r.children[0].textContent), ['1', '2', '3', '4']);
});

for (const paused of [false, true]) {
  test(`loss survives small browser limits while ${paused ? 'paused' : 'waiting to render'}`, (t) => {
    const h = setup(t, ['a'], 2);
    if (paused) $('pause').click();
    h.source.emit('packet_gap', { after: 0, next: 2, missed: 1 });
    h.send(2, { evicted: 3, skipped: 0 });
    for (let seq = 3; seq <= 8; seq++) h.send(seq, { skipped: 0 });
    if (paused) $('pause').click();
    h.flush();
    assert.deepEqual(h.rows().map((r) => r.dataset.seq), ['7', '8']);
    assert.equal($('prows').children.length, 2);
    assert.equal($('sampled').textContent, 'Capture: 3 copies evicted · Subscriber: 1 rows missed');
    // Gap notices are bounded even if no rows survive server retention.
    for (let seq = 9; seq <= 12; seq++) {
      h.source.emit('packet_gap', { after: seq - 1, next: seq + 1, missed: 1 });
    }
    h.flush();
    assert.equal($('prows').children.length, 2);
    assert.equal($('prows').children.every((r) => r.classList.contains('gap')), true);
    assert.equal($('sampled').textContent, 'Capture: 3 copies evicted · Subscriber: 5 rows missed');
  });
}

test('reconnect and reopen reset loss totals and ignore an old stream', (t) => {
  const h = setup(t);
  for (let reconnect = 0; reconnect < 3; reconnect++) {
    h.source.emit('packet_gap', { after: 0, next: 3, missed: 2 });
    h.send(3, { evicted: 4, skipped: 0 });
    assert.equal($('sampled').textContent, 'Capture: 4 copies evicted · Subscriber: 2 rows missed');
    h.source.emit('open');
    h.flush();
    assert.equal($('sampled').hidden, true);
    assert.equal($('sampled').textContent, '');
    assert.equal(h.rows().length, 0);
  }
  h.send(3, { evicted: 4 });
  h.open();
  h.source.emit('packet_gap', { after: 0, next: 3, missed: 2 });
  h.send(4, { evicted: 8 });
  assert.equal($('sampled').hidden, true);
  assert.equal($('sampled').textContent, '');
  assert.equal(h.rows().length, 0);
});

async function pending(request, stage) {
  let resolve, reject;
  if (stage.startsWith('json')) {
    request.resolve({ ok: true, json: () => new Promise((done, fail) => { resolve = done; reject = fail; }) });
    await settle();
  }
  return () => {
    if (stage === 'json') resolve(detail(1));
    else if (stage === 'json failure') reject(new Error('Invalid JSON'));
    else if (stage === 'fetch failure') request.reject(new Error('Disconnected'));
    else request.resolve({ ok: stage !== 'missing', json: async () => detail(1) });
  };
}

function assertEmptyHex() {
  assert.equal($('hex').hidden, true);
  assert.equal($('hex-tabs').textContent, '');
  assert.equal($('hex-dump').textContent, '');
  $('tree').dispatchEvent(new Event('pointerleave'));
  assert.equal($('hex-dump').textContent, '');
}

for (const stage of ['fetch', 'json', 'missing', 'fetch failure', 'json failure']) {
  test(`a newer selection wins over an older ${stage} completion`, async (t) => {
    const h = setup(t, ['a', 'b']);
    h.send(1, { link: 'a' });
    h.send(1, { link: 'b', side: 1 });
    h.flush();
    const [first, second] = h.rows();
    first.click();
    const old = h.requests[0];
    const complete = await pending(old, stage);
    second.click();
    assert.equal(old.signal.aborted, true);
    assert.equal(h.requests[1].signal.aborted, false);
    assert.match(h.requests[1].url, /link=b&seq=1/);
    h.requests[1].resolve({ ok: true, json: async () => detail(2) });
    await settle();
    const tree = $('tree').textContent;
    const hex = $('hex-dump').textContent;
    assert.match(tree, /Packet 2.*To → From/);
    assert.match(hex, /41 42/);
    complete(); // The mock deliberately completes even after abort.
    await settle();
    assert.deepEqual($('prows').querySelectorAll('tr.on'), [second]);
    assert.equal($('tree').textContent, tree);
    assert.equal($('hex-dump').textContent, hex);
  });
}

for (const action of ['close', 'reopen', 'reconnect']) {
  for (const stage of ['fetch', 'json']) {
    test(`${action} invalidates a pending detail ${stage}`, async (t) => {
      const h = setup(t);
      h.send(1);
      h.flush();
      h.rows()[0].click();
      const request = h.requests[0];
      const complete = await pending(request, stage);
      if (action === 'close') h.view.close();
      else if (action === 'reopen') h.view.openLinks('Other', 'Link', [{ e: { id: 'b' }, flip: false }]);
      else h.source.emit('open');
      assert.equal(request.signal.aborted, true);
      const tree = $('tree').textContent;
      complete();
      await settle();
      assert.equal($('tree').textContent, tree);
      assertEmptyHex();
    });
  }
}

for (const stage of ['missing', 'fetch failure', 'json failure']) {
  test(`${stage} clears the selected tree and bytes and permits retry`, async (t) => {
    const h = setup(t);
    h.send(1);
    h.flush();
    const row = h.rows()[0];
    row.click();
    h.requests[0].resolve({ ok: true, json: async () => detail(1) });
    await settle();
    assert.match($('tree').textContent, /Packet 1/);
    assert.match($('hex-dump').textContent, /41 42/);
    assert.equal($('hex-tabs').children.length, 2);
    row.click();
    assert.match($('tree').textContent, /Loading/);
    assertEmptyHex();
    const complete = await pending(h.requests[1], stage);
    complete();
    await settle();
    assert.match($('tree').textContent, stage === 'missing' ? /no longer kept/ : /Could not load/);
    assertEmptyHex();
    row.click();
    h.requests[2].resolve({ ok: true, json: async () => detail(1) });
    await settle();
    assert.match($('tree').textContent, /Packet 1/);
    assert.equal($('hex').hidden, false);
  });
}

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

test('capture downloads use the transport for the current links', (t) => {
  const h = setup(t, ['a', 'b']);
  $('pcap').click();
  assert.deepEqual(h.downloads, [['pcap', 'a,b']]);
  h.view.close();
  $('pcap').click();
  assert.equal(h.downloads.length, 1);
});

test('a successful capture download clears the previous failure label', async (t) => {
  const h = setup(t);
  h.failDownload(new Error('Download unavailable'));
  $('pcap').click();
  await settle();
  assert.equal($('pcap-label').textContent, 'Download failed. Try again.');
  h.failDownload(null);
  $('pcap').click();
  await settle();
  assert.equal($('pcap-label').textContent, 'Capture for Wireshark');
});
