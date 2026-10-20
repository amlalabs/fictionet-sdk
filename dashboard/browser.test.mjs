// A real browser regression for two ports on the same host. No npm packages.
// Set CHROMIUM to a Chromium executable if it is not named `chromium`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const exec = promisify(execFile);

async function checkPacketLayout() {
  const { mount } = await import('./components/packets.mjs');
  const { createSelection } = await import('./selection.mjs');
  const { hostLookups } = await import('./page.mjs');
  const check = (value, message) => { if (!value) throw new Error(message); };
  const css = document.createElement('link');
  css.rel = 'stylesheet'; css.href = '/page.css';
  const loaded = new Promise((resolve, reject) => { css.onload = resolve; css.onerror = reject; });
  document.head.append(css);
  await loaded;
  const root = document.createElement('section');
  root.style.cssText = 'width:530px;height:500px;display:flex';
  document.body.append(root);
  class Source extends EventTarget {
    emit(type, data) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
    close() {}
  }
  const source = new Source();
  // The graph holds one sandbox per host, each with one link: link `a` for
  // the first host, `b` for the second. The list shows every host's links.
  const listeners = new Set();
  const graph = { state: { known: true, nodes: new Map(), edges: new Map() }, subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); } };
  let hosts = [];
  const scenario = (names) => {
    hosts = names.map((name) => ({ name, sandbox: name }));
    graph.state.nodes = new Map([['t1', { id: 't1', kind: 'task' }], ...names.map((name) => [`s-${name}`, { id: `s-${name}`, kind: 'sandbox', name }])]);
    graph.state.edges = new Map(names.map((name, index) => ['ab'[index], { id: 'ab'[index], a: `s-${name}`, b: 't1', c: [0, 0, 0, 0] }]));
    listeners.forEach((listener) => listener('snapshot'));
  };
  const dispose = mount(root, {
    selection: createSelection(), graph, get hosts() { return hosts; }, ...hostLookups(() => hosts),
    transport: { packetStream: () => source, get: async () => ({ links: [] }) },
  });
  scenario(['alpha', 'beta']);
  const send = (seq, src, dst, t = seq / 1000) => source.emit('packet', {
    link: 'a', seq, src, dst, proto: 'ICMP', info: 'Echo (ping) reply id=0x1234',
    t, side: 0, len: 28, tags: [],
  });
  send(1, '10.0.0.2', '10.0.0.3', 11.0039);
  send(2, '255.255.255.255', '192.168.100.200', 1000.0039);
  const frame = () => new Promise(requestAnimationFrame);
  while (root.querySelectorAll('#prows tr').length < 2) await frame();
  const $ = (selector) => root.querySelector(selector);
  check($('td.c-src').textContent === '10.0.0.2' && $('td.c-dst').textContent === '10.0.0.3', 'IPv4 address changed');
  const whole = (cell) => {
    const range = document.createRange(); range.selectNodeContents(cell);
    const text = range.getBoundingClientRect(), bounds = cell.getBoundingClientRect();
    check(text.left >= bounds.left && text.right <= bounds.right - 7, 'text exceeds its column: ' + cell.textContent);
    check(getComputedStyle(cell).textOverflow !== 'ellipsis', 'text can ellipsize: ' + cell.textContent);
  };
  // A gap row spans every column; the header must still fill the table.
  source.emit('error', { error: 'Connection dropped. Reconnecting.' });
  while (!root.querySelector('#prows tr.gap')) await frame();
  // A hidden column keeps its place at zero width and shows nothing.
  const hidden = (cell) => getComputedStyle(cell).visibility === 'hidden' && cell.getBoundingClientRect().width < 1;
  // These links name two hosts, so the list has a Host column and Protocol
  // joins Info below 640 px; a single host's list keeps it to 560 px.
  for (const width of [530, 559, 559.5, 560, 599, 599.5, 600, 639, 639.5, 640, 800, 530]) {
    const merged = width < 640;
    root.style.width = width + 'px';
    await frame();
    for (const cell of root.querySelectorAll('#prows tr:not(.gap) td.c-src, #prows tr:not(.gap) td.c-dst, #prows tr:not(.gap) td.c-time')) whole(cell);
    check($('td.c-time').textContent === '11.0039' && $('#prows tr:nth-child(2) .c-time').textContent === '1000.0039', 'Time changed');
    check(hidden($('td.c-proto')) === merged, 'Protocol breakpoint');
    for (const column of ['c-no', 'c-len']) check(hidden($('td.' + column)) === (width < 600), column + ' breakpoint');
    check(!hidden($('td.c-time')), 'Time hidden');
    check(Math.abs($('th.c-info').getBoundingClientRect().right - $('#plist table').getBoundingClientRect().right) < 1, 'columns do not fill the table');
    const prefix = $('.packet-info-protocol');
    check((getComputedStyle(prefix).display !== 'none') === merged, 'protocol prefix visibility');
    if (merged) {
      check($('td.c-info').innerText.startsWith('ICMP Echo (ping) reply'), 'protocol missing from Info');
      check(getComputedStyle(prefix).fontWeight === '600', 'protocol weight');
    }
    check($('#pfilter').getBoundingClientRect().width >= 160, 'filter too narrow');
    check($('#plist').scrollWidth <= $('#plist').clientWidth, 'IPv4 table overflows');
  }
  // Below 480 px the addresses give way so Info keeps room; each address
  // stays whole in its title.
  root.style.width = '420px';
  await frame();
  check($('th.c-info').getBoundingClientRect().width >= 60, 'Info has no room in a narrow list: ' + $('th.c-info').getBoundingClientRect().width);
  for (const column of ['c-src', 'c-dst']) {
    const address = $('th.' + column).getBoundingClientRect().width, info = $('th.c-info').getBoundingClientRect().width;
    check(info > address * 1.2, `${column} did not give way to Info: ${address} against ${info}`);
  }
  for (const cell of root.querySelectorAll('#prows tr:not(.gap) td.c-src, #prows tr:not(.gap) td.c-dst')) check(cell.title === cell.textContent, 'address without its full title: ' + cell.textContent);
  root.style.width = '530px';
  await frame();
  const title = $('#drawer-title');
  check(title.title === title.textContent && title.getAttribute('aria-label') === title.textContent, 'incomplete title accessibility');
  $('#jump-packets').hidden = false;
  $('#jump-packets').textContent = '↓ 9 new';
  await frame();
  check(title.scrollWidth > title.clientWidth && getComputedStyle(title).textOverflow === 'ellipsis', 'title did not yield space');
  check($('#pfilter').getBoundingClientRect().width >= 160, 'new packets button squeezed filter');
  check($('#pcap').getBoundingClientRect().right <= root.getBoundingClientRect().right, 'toolbar overflows');
  const src = '[2001:db8:1234:5678:90ab:cdef:1234:5678]:65535';
  const dst = '192.168.100.200:65535';
  send(3, src, dst, 1001.0039);
  while (root.querySelectorAll('#prows tr:not(.gap)').length < 3) await frame();
  const last = [...root.querySelectorAll('#prows tr:not(.gap)')].at(-1);
  check(last.querySelector('.c-src').textContent === src && last.querySelector('.c-dst').textContent === dst, 'long address changed');
  for (const cell of root.querySelectorAll('td.c-src, td.c-dst, td.c-time')) whole(cell);
  scenario(['workstation1', 'jump']);
  for (const width of [530, 600]) {
    root.style.width = width + 'px';
    const rows = root.querySelectorAll('#prows tr').length;
    send(4, '10.0.0.2', '10.0.0.3');
    while (root.querySelectorAll('#prows tr').length < rows + 1) await frame();
    const host = $('td.c-host'), bounds = host.getBoundingClientRect();
    const range = document.createRange(); range.selectNodeContents(host);
    check(host.textContent === 'workstation1', 'host name changed');
    check(range.getBoundingClientRect().right <= bounds.right - 7, 'host name truncated');
    send(5, '10.0.0.2', '10.0.0.3');
    while (root.querySelectorAll('#prows tr').length < rows + 2) await frame();
    check(host.getBoundingClientRect().width === bounds.width, 'host column moved');
    check($('#plist').scrollWidth <= $('#plist').clientWidth, 'host column overflows');
  }
  // A single host's list has no Host column and keeps Protocol to 560 px.
  scenario(['alpha']);
  send(6, '10.0.0.2', '10.0.0.3');
  while (!root.querySelector('#prows tr:not(.gap)')) await frame();
  check(!root.querySelector('.packet-panel').classList.contains('merged-hosts'), 'one host shows a Host column');
  for (const width of [559, 560, 639]) {
    root.style.width = width + 'px';
    await frame();
    check(hidden($('#prows tr:not(.gap) td.c-proto')) === (width < 560), 'single-host Protocol breakpoint at ' + width);
  }
  dispose(); root.remove(); css.remove();
}

async function checkContainmentLayout() {
  const { mount } = await import('./components/containment.mjs');
  const { createSelection } = await import('./selection.mjs');
  const check = (value, message) => { if (!value) throw new Error(message); };
  const css = document.createElement('link');
  css.rel = 'stylesheet'; css.href = '/page.css';
  const loaded = new Promise((resolve, reject) => { css.onload = resolve; css.onerror = reject; });
  document.head.append(css);
  await loaded;
  const root = document.createElement('section');
  document.body.append(root);
  const outcomes = ['contained', 'not_contained', 'unknown', 'missing_tool', 'timed_out', 'fact'];
  const probes = outcomes.map((outcome) => ({
    guest: 'east', name: 'Public DNS', command: 'dig @8.8.8.8 example.com', destination: '8.8.8.8:53', guest_result: 'connection timed out; no servers could be reached',
    summary: 'connection timed out; no servers could be reached', world_answer: 'no route: no machine at that address', outcome,
  }));
  const hosts = [{ name: 'east', sandbox: 'east' }];
  const { hostLookups } = await import('./page.mjs');
  const dispose = mount(root, {
    selection: createSelection(), hosts, ...hostLookups(() => hosts),
    state: (_, update) => { update({ value: { probes } }); return () => {}; },
  }, { state: 'containment' });
  // The inspector is about 530 px wide at 1280 and 457 px in a shared workspace at 1440.
  for (const width of [530, 457]) {
    root.style.width = width + 'px';
    await new Promise(requestAnimationFrame);
    for (const pill of root.querySelectorAll('.outcome-pill')) {
      const label = [...pill.childNodes].find((node) => node.nodeType === Node.TEXT_NODE);
      const range = document.createRange(); range.selectNode(label);
      const lines = range.getClientRects(), icon = pill.querySelector('svg').getBoundingClientRect();
      check(lines.length === 1, `${label.textContent} wraps at ${width} px`);
      check(icon.right <= lines[0].left, `${label.textContent} has its icon above it at ${width} px`);
    }
  }
  dispose(); root.remove(); css.remove();
}

// World data reaches the page as text: markup in it never becomes elements
// or runs, in any panel.
async function checkTextStaysText() {
  const check = (value, message) => { if (!value) throw new Error(message); };
  const panels = {
    events: await import('./components/events.mjs'),
    table: await import('./components/table.mjs'),
    containment: await import('./components/containment.mjs'),
    leftTheBox: await import('./components/left-the-box.mjs'),
    labels: await import('./components/labels.mjs'),
    packets: await import('./components/packets.mjs'),
    map: await import('./components/map.mjs'),
  };
  const { createSelection } = await import('./selection.mjs');
  const { createState } = await import('./state.mjs');
  const { hostLookups } = await import('./page.mjs');
  const markup = '<img src=x onerror="window.injected=true"><fictionet-injected>tag</fictionet-injected>';
  const graph = createState();
  graph.snapshot({
    t: 1, started: 0, ended: false, status: null,
    nodes: [{ id: 's1', kind: 'sandbox', name: 'alpha' }, { id: 't1', kind: 'task', name: markup, file: markup, line: 1 }],
    edges: [{ id: 'e1', a: 's1', b: 't1', label: markup }], counters: { e1: [1, 40, 0, 0] },
    events: [{ seq: 1, at: 1, source: 'http', kind: 'request', summary: markup, fields: { host: markup }, sandbox: { name: 'alpha' }, task: markup, node: 't1' }],
  });
  const hosts = [{ name: 'alpha', sandbox: 'alpha' }];
  const values = {
    '/api/state/rows': [{ name: markup }],
    '/api/state/containment': { probes: [{ guest: 'alpha', name: markup, command: markup, destination: markup, outcome: 'not_contained', guest_result: markup, summary: markup, world_answer: markup, proxies: [{ name: markup, destination: markup, world_host: false }] }] },
    '/api/state/labels': [{ id: 1, text: markup, target: { kind: 'event', seq: 1 }, at: 1 }],
  };
  class Source extends EventTarget {
    emit(type, data) { this.dispatchEvent(new MessageEvent(type, { data: JSON.stringify(data) })); }
    close() {}
  }
  const source = new Source();
  const services = {
    selection: createSelection(), graph: { ...graph, subscribe: () => () => {} }, hosts, ...hostLookups(() => hosts),
    state: (path, update) => { update({ revision: 1, value: values[path], status: {} }); return () => {}; },
    labelState: '/api/state/labels', labelCommand: '/api/command/labels', containmentState: '/api/state/containment',
    transport: {
      get: async (path) => (path === '/api/egress'
        ? { revision: 1, dropped: 0, lost: 0, pending: [], lookups: [{ sandbox: 'alpha', name: markup, answer: markup, count: 1, first: 1, last: 1 }], destinations: [{ sandbox: 'alpha', name: markup, address: markup, transport: 'tcp', outcome: 'forwarded', by: markup, requests: 1, connections: 1, packets: 0, unanswered: 0, first: 1, last: 1 }] }
        : { links: [] }),
      packetStream: () => source,
    },
  };
  const options = {
    events: {}, map: {}, packets: {}, leftTheBox: {},
    table: { state: '/api/state/rows', columns: [{ label: markup, pointer: '/name', format: 'text' }] },
    containment: { state: '/api/state/containment' },
    labels: { state: '/api/state/labels', command: '/api/command/labels' },
  };
  const disposals = [];
  const roots = [];
  for (const [name, { mount }] of Object.entries(panels)) {
    const root = document.createElement('section');
    root.style.cssText = 'width:600px;height:400px;display:flex;flex-direction:column';
    document.body.append(root);
    roots.push(root);
    disposals.push(mount(root, services, options[name]));
  }
  source.emit('packet', { link: 'e1', seq: 1, t: 1, side: 0, len: 40, tags: [], src: markup, dst: markup, proto: markup, info: markup });
  // Select the event so its fields open below its line.
  services.selection.set({ event: graph.state.events[0] });
  for (let i = 0; i < 10; i++) await new Promise(requestAnimationFrame);
  for (const [index, name] of Object.keys(panels).entries()) {
    check(roots[index].textContent.includes('<fictionet-injected>'), `${name} does not show the markup as text`);
    check(!roots[index].querySelector('img, fictionet-injected'), `${name} made the markup an element`);
  }
  check(!window.injected, 'markup ran');
  disposals.forEach((dispose) => dispose());
  roots.forEach((root) => root.remove());
}

test('browser bootstrap, reconnect and downloads keep credentials away from another port', async (t) => {
  const chromium = process.env.CHROMIUM || 'chromium';
  try { await exec(chromium, ['--version'], { timeout: 10000 }); } catch (error) {
    assert.fail(`Chromium is unavailable (${error.message}); set CHROMIUM to run the two-origin regression`);
  }
  const profile = await mkdtemp(join(tmpdir(), 'fictionet-browser-'));
  t.after(() => rm(profile, { recursive: true, force: true }));
  const received = [], foreign = [];
  let layoutReport;
  let streams = 0, bootstraps = 0;
  let recordResult;
  const reported = new Promise((resolve, reject) => {
    recordResult = (req, res) => {
      let report = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => { report += chunk; });
      req.on('end', () => {
        res.writeHead(204).end();
        resolve({ report });
      });
      req.on('error', reject);
    };
  });
  const serve = async (handler) => {
    const server = createServer(handler);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(() => { server.closeAllConnections(); server.close(); });
    return `http://127.0.0.1:${server.address().port}`;
  };
  const other = await serve((req, res) => {
    foreign.push({ url: req.url, ...req.headers });
    if (req.url === '/result') { recordResult(req, res); return; }
    res.setHeader('Content-Type', 'text/html');
    res.end(`<body>Checking other origin<script>
      const isolated = sessionStorage.getItem('fictionet_token') === null && !document.cookie.includes('fictionet_token');
      document.body.textContent = isolated ? 'PASS: isolated' : 'FAIL: leaked storage';
      ${req.url === '/probe' ? `if (isolated) location.replace(${JSON.stringify(origin + '/reload#token=browser-test-token')}); else` : ''}
      fetch('/result', { method: 'POST', credentials: 'omit', body: document.body.textContent });
    </script>`);
  });
  const origin = await serve(async (req, res) => {
    received.push({ url: req.url, ...req.headers });
    if (req.url === '/layout-result') {
      layoutReport = '';
      req.setEncoding('utf8');
      for await (const chunk of req) layoutReport += chunk;
      res.writeHead(204).end();
      return;
    }
    if (req.url === '/result') { recordResult(req, res); return; }
    if (req.url.endsWith('.mjs') || req.url.endsWith('.css')) {
      res.setHeader('Content-Type', req.url.endsWith('.css') ? 'text/css' : 'text/javascript');
      res.end(await readFile(new URL('.' + req.url, import.meta.url)));
      return;
    }
    if (req.url.startsWith('/api/')) {
      if (req.headers.authorization !== 'Bearer browser-test-token') {
        res.writeHead(401).end(); return;
      }
      if (req.url === '/api/bootstrap') {
        res.writeHead(++bootstraps === 1 ? 204 : 401).end(); return;
      }
      if (req.url.startsWith('/api/packets?')) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.end(`event: packet\ndata: ${++streams}\n\n`);
        return;
      }
      if (req.url.includes('seq=2')) {
        res.writeHead(302, { Location: `${other}/redirect` }).end(); return;
      }
      res.end('{}'); return;
    }
    res.setHeader('Content-Type', 'text/html');
    res.end(`<body>Running<script type="module">
      import { createTransport } from '/transport.mjs';
      const check = (value, message) => { if (!value) throw new Error(message); };
      try {
        const transport = createTransport({});
        await transport.packet({ link: 'e1', seq: 1 });
        check(!location.hash, 'fragment remained');
        check(sessionStorage.getItem('fictionet_token') === 'browser-test-token', 'missing session');
        check(!document.cookie.includes('fictionet_token'), 'cookie created');
        if (location.pathname === '/') {
          try {
            await (${checkPacketLayout.toString()})();
            await (${checkContainmentLayout.toString()})();
            await (${checkTextStaysText.toString()})();
            await fetch('/layout-result', { method: 'POST', body: 'PASS' });
          } catch (error) {
            await fetch('/layout-result', { method: 'POST', body: error.message });
            throw error;
          }
          await new Promise((resolve) => {
            addEventListener('hashchange', resolve, { once: true });
            location.hash = '#token=browser-test-token';
          });
          check(!location.hash, 'fragment navigation retained token');
          await transport.packet({ link: 'e1', seq: 1 });
          check(sessionStorage.getItem('fictionet_token') === 'browser-test-token', 'fragment navigation lost session');
          let reconnects = 0;
          await new Promise((resolve) => {
            const source = transport.packetStream('e1', () => reconnects++);
            source.addEventListener('packet', (event) => {
              if (event.data === '2') { source.close(); resolve(); }
            });
          });
          check(reconnects === 1, 'stream did not reconnect');
          let redirected = false;
          try { await transport.packet({ link: 'e1', seq: 2 }); redirected = true; } catch {}
          check(!redirected, 'redirect followed');
          let downloads = 0;
          const downloader = createTransport({}, { document: {
            body: document.body,
            createElement() {
              const anchor = document.createElement('a');
              anchor.click = function () {
                check(this.isConnected, 'detached download');
                check(this.href.startsWith('blob:'), 'non-blob download');
                downloads++;
              };
              return anchor;
            },
          } });
          await downloader.download('pcap', 'e1');
          check(downloads === 1, 'missing download');
          downloader.close();
          transport.close();
          location.replace(${JSON.stringify(other + '/probe')});
        } else {
          transport.logout();
          check(sessionStorage.getItem('fictionet_token') === null, 'logout retained token');
          let accepted = false;
          try { await transport.packet({ link: 'e1', seq: 1 }); accepted = true; } catch {}
          check(!accepted, 'request after logout');
          location.replace(${JSON.stringify(other + '/done')});
        }
      } catch (error) {
        document.body.textContent = 'FAIL: ' + error.message;
        await fetch('/result', { method: 'POST', credentials: 'omit', body: document.body.textContent });
      }
    </script>`);
  });
  // Streaming fetch bodies can outlive Chromium's virtual-time budget. Wait for the page's report.
  const browser = spawn(chromium, [
    '--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    '--no-first-run', '--no-default-browser-check', `--user-data-dir=${profile}`,
    // The throwaway profile must not wait on the desktop keyring, which can be locked.
    '--password-store=basic', '--use-mock-keychain', `${origin}/#token=browser-test-token`,
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  browser.stderr.setEncoding('utf8');
  browser.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4096); });
  const exited = new Promise((resolve) => browser.once('exit', (code, signal) => resolve({ code, signal })));
  const failed = new Promise((resolve) => browser.once('error', (error) => resolve({ error })));
  const closed = new Promise((resolve) => browser.once('close', resolve));
  const stop = async () => {
    if (browser.pid && browser.exitCode === null && browser.signalCode === null) browser.kill();
    await closed;
  };
  t.after(stop);
  let timer;
  const deadline = new Promise((resolve) => { timer = setTimeout(() => resolve({ timeout: true }), 30000); });
  let outcome;
  try {
    outcome = await Promise.race([reported, exited, failed, deadline]);
  } finally {
    clearTimeout(timer);
    await stop();
  }
  const diagnostics = `Chromium stderr (tail):\n${stderr}\nOrigin requests: ${received.map((r) => r.url).join(', ')}\nOther origin requests: ${foreign.map((r) => r.url).join(', ')}`;
  // The --version probe passed, so Chromium is installed. A launch error or early exit is a failure.
  if (outcome.error) assert.fail(`Chromium failed to launch (${outcome.error.message})\n${diagnostics}`);
  if ('code' in outcome) {
    assert.fail(`Chromium exited before reporting a result (code ${outcome.code}, signal ${outcome.signal})\n${diagnostics}`);
  }
  if (outcome.timeout) assert.fail(`Chromium did not report a result within 30 s\n${diagnostics}`);
  await t.test('narrow packets keep whole addresses and times, move Protocol into Info and preserve the filter width; containment labels stay on one line; world data stays text', () => {
    assert.equal(layoutReport, 'PASS');
  });
  assert.match(outcome.report, /^PASS: isolated$/);
  assert.equal(bootstraps, 3);
  assert.equal(streams, 2);
  assert.ok(received.some((r) => r.url.startsWith('/api/pcap?')));
  assert.ok(received.some((r) => r.url === '/reload'));
  assert.ok(received.every((r) => !r.cookie && !r.url.includes('browser-test-token')));
  assert.ok(foreign.some((r) => r.url === '/probe'));
  assert.ok(foreign.some((r) => r.url === '/done'));
  assert.ok(foreign.every((r) => !r.cookie && !r.authorization));
});
