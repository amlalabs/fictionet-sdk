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

test('browser bootstrap, reconnect and downloads keep credentials away from another port', async (t) => {
  const chromium = process.env.CHROMIUM || 'chromium';
  try { await exec(chromium, ['--version'], { timeout: 10000 }); } catch (error) {
    assert.fail(`Chromium is unavailable (${error.message}); set CHROMIUM to run the two-origin regression`);
  }
  const profile = await mkdtemp(join(tmpdir(), 'fictionet-browser-'));
  t.after(() => rm(profile, { recursive: true, force: true }));
  const received = [], foreign = [];
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
  const state = await readFile(new URL('./state.mjs', import.meta.url));
  const transport = await readFile(new URL('./transport.mjs', import.meta.url));
  const origin = await serve((req, res) => {
    received.push({ url: req.url, ...req.headers });
    if (req.url === '/result') { recordResult(req, res); return; }
    if (req.url === '/legacy') {
      res.writeHead(302, {
        'Set-Cookie': 'fictionet_token=browser-test-token; Path=/; HttpOnly; SameSite=Strict',
        Location: '/#token=browser-test-token',
      }).end();
      return;
    }
    if (req.url === '/') res.setHeader('Set-Cookie', 'fictionet_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict');
    if (req.url === '/state.mjs') {
      res.setHeader('Content-Type', 'text/javascript');
      res.end(state);
      return;
    }
    if (req.url === '/transport.mjs') {
      res.setHeader('Content-Type', 'text/javascript');
      res.end(transport);
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
    '--password-store=basic', '--use-mock-keychain', `${origin}/legacy`,
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
  assert.match(outcome.report, /^PASS: isolated$/);
  assert.equal(bootstraps, 3);
  assert.equal(streams, 2);
  assert.ok(received.some((r) => r.url.startsWith('/api/pcap?')));
  assert.ok(received.some((r) => r.url === '/reload'));
  assert.equal(received.find((r) => r.url === '/').cookie, 'fictionet_token=browser-test-token');
  assert.ok(received.every((r) => (r.url === '/' || !r.cookie) && !r.url.includes('browser-test-token')));
  assert.ok(foreign.some((r) => r.url === '/probe'));
  assert.ok(foreign.some((r) => r.url === '/done'));
  assert.ok(foreign.every((r) => !r.cookie && !r.authorization));
});
