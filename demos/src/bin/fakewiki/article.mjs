// Article text and delivery facts come from separate world projections.
export function mount(root, services, options = {}) {
  const el = (tag, text, parent, cls) => {
    const node = root.ownerDocument.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (cls) node.setAttribute('class', cls);
    parent?.appendChild(node);
    return node;
  };
  root.classList.add('article-container');
  const cleanup = [], dynamic = [];
  const listen = (target, type, fn, list = cleanup) => {
    target.addEventListener(type, fn);
    list.push(() => target.removeEventListener(type, fn));
  };
  const controller = new AbortController();
  const sheet = el('link', undefined, root);
  sheet.setAttribute('rel', 'stylesheet'); sheet.setAttribute('href', '/assets/article.css');
  const panel = el('div', undefined, root, 'article-panel');
  const switchRow = el('div', undefined, panel, 'article-switch-row');
  const toggle = el('button', undefined, switchRow, 'switch article-switch');
  const track = el('span', undefined, toggle, 'switch-track');
  track.setAttribute('aria-hidden', 'true');
  el('span', undefined, track, 'switch-knob');
  const switchLabel = el('span', 'Waiting for state…', toggle, 'article-switch-label');
  toggle.type = 'button'; toggle.setAttribute('role', 'switch'); toggle.setAttribute('aria-label', 'Tamper');
  const revision = el('p', '', switchRow, 'article-meta');
  const reply = el('p', '', panel, 'article-reply'); reply.setAttribute('role', 'status');
  const address = el('div', undefined, panel, 'article-address');
  const where = el('div', undefined, address, 'article-where');
  const url = el('div', 'Waiting for the article…', where, 'article-url');
  const identity = el('p', '', where, 'article-meta');
  const follow = el('button', 'Following reads', address, 'text-button'); follow.type = 'button';
  address.hidden = true;
  const pickers = el('div', undefined, panel, 'article-pickers');
  pickers.hidden = true;
  const topics = el('div', undefined, pickers, 'article-topics segmented');
  topics.setAttribute('role', 'group'); topics.setAttribute('aria-label', 'Topic');
  const chips = el('div', undefined, pickers, 'article-chips');
  chips.setAttribute('role', 'group'); chips.setAttribute('aria-label', 'Source');
  const body = el('div', undefined, panel, 'article-body');
  const loading = el('div', undefined, body, 'article-loading');
  loading.setAttribute('role', 'status');
  el('strong', 'Waiting for the article versions', loading);
  el('p', 'The world has not published the article yet. The real and tampered versions appear here when it does.', loading);
  const history = el('div', undefined, panel, 'article-history');
  history.setAttribute('role', 'group'); history.setAttribute('aria-label', 'Reads and switch changes in this run');
  history.hidden = true;
  const loss = el('p', '', panel, 'article-meta article-loss'); loss.setAttribute('role', 'status');
  // New reads are announced once here; the visible marker moves between renders.
  const announce = el('p', '', panel, 'article-announce'); announce.setAttribute('aria-live', 'polite');
  const readMarker = el('div', undefined, undefined, 'article-read');
  let markedRead = -1;
  let state, diff, hosts = {}, readerHost, reader = 'Reader (scripted)', topicName, sourceName, pinned = false, busy = false, disposed = false;
  let events = [], incomplete = false;
  const LIMIT = 2000;
  const seconds = (duration) => (duration?.secs || 0) + (duration?.nanos || 0) / 1e9;
  const time = (at) => services.format.fmtRunTime(at).replace(/\s*s$/, ' s');
  const isRead = (event) => event.source === 'http' && event.kind === 'request'
    && ['real', 'tampered'].includes(event.fields?.served)
    && event.fields?.status === 200 && event.fields?.complete === true && event.fields?.method === 'GET';
  const knownRead = (event) => isRead(event) && readerHost && event.sandbox?.name === readerHost && Object.hasOwn(hosts, event.fields.host);
  const readsFor = (topic, source) => events.filter((event) => knownRead(event) && event.fields.topic === topic && event.fields.source === source);
  function switchState() {
    toggle.disabled = !state || busy;
    toggle.setAttribute('aria-checked', String(Boolean(state?.on)));
    toggle.setAttribute('aria-busy', String(busy));
    panel.dataset.state = state ? (state.on ? 'on' : 'off') : 'waiting';
    switchLabel.textContent = !state ? 'Waiting for state…' : busy ? 'Changing…' : state.on ? 'Serving the tampered article' : 'Serving the real article';
    revision.textContent = state ? `${state.scope === 'wikipedia' ? 'Wikipedia only · ' : state.scope === 'all_sources' ? 'All sources · ' : ''}Revision ${state.revision} · ${state.revision ? 'changed at' : 'initial state at'} ${time(seconds(state.since_start))}` : 'Waiting for the world';
  }
  // Marks keep their order and stay at least 14 px apart; titles keep exact times.
  function spread(fractions, width) {
    const gap = Math.min(14 / width, 1 / Math.max(fractions.length, 1));
    const out = [];
    for (const [index, fraction] of fractions.entries()) out.push(Math.max(fraction, index ? out[index - 1] + gap : 0));
    for (let index = out.length - 1; index >= 0; index--) out[index] = Math.min(out[index], 1 - (out.length - 1 - index) * gap);
    return out;
  }
  function render() {
    if (disposed || !diff) return;
    const focused = root.ownerDocument.activeElement;
    const focusKey = focused?.getAttribute?.('data-focus');
    dynamic.splice(0).forEach((off) => off());
    const latest = events.filter(knownRead).at(-1);
    if (!pinned && latest) { topicName = latest.fields.topic; sourceName = latest.fields.source; }
    let topic = diff.topics.find((item) => item.topic === topicName)
      || diff.topics.find((item) => item.sources.some((source) => source.url === 'https://en.wikipedia.org/wiki/Stream_ripping'))
      || diff.topics[0];
    if (!topic) return;
    topicName = topic.topic;
    const source = topic.sources.find((item) => item.source === sourceName) || topic.sources.find((item) => item.source === 'wikipedia') || topic.sources[0];
    sourceName = source.source;
    const reads = readsFor(topicName, sourceName), last = reads.at(-1);
    const readerName = reader.replace(/ \(scripted\)$/, '').replace(/^./u, (letter) => letter.toUpperCase());
    const parsed = new URL(source.url);
    url.textContent = last ? `${last.fields.scheme}://${last.fields.host}${last.fields.path}${last.fields.query ? `?${last.fields.query}` : ''}` : source.url;
    identity.textContent = `${hosts[parsed.hostname] || 'Address loading'} · same host, address and certificate for both versions`;
    url.setAttribute('title', url.textContent);
    identity.setAttribute('title', identity.textContent);
    where.setAttribute('title', `${url.textContent} · ${identity.textContent}${last ? '' : ' · Not read yet'}`);
    panel.dataset.on = String(diff.on);
    pickers.hidden = false; address.hidden = false; history.hidden = false;
    follow.textContent = pinned ? 'Follow latest read' : 'Following reads';
    topics.replaceChildren();
    for (const item of diff.topics) {
      const title = item.sources.find((source) => new URL(source.url).hostname === 'en.wikipedia.org')?.real.title || item.topic;
      const button = el('button', title, topics);
      button.setAttribute('title', title); button.setAttribute('data-focus', `topic-${item.topic}`);
      button.type = 'button'; button.setAttribute('aria-pressed', String(item.topic === topicName));
      listen(button, 'click', () => { pinned = true; topicName = item.topic; sourceName = undefined; render(); }, dynamic);
    }
    chips.replaceChildren();
    for (const item of topic.sources) {
      const read = readsFor(topicName, item.source).length > 0;
      const host = new URL(item.url).hostname;
      const caption = `${host} · ${item.served} · ${read ? 'read' : 'unread'}`;
      const chip = el('button', undefined, chips);
      el('span', host, chip, 'article-source-host');
      if (item.served === 'tampered') el('span', 'Tampered', chip, 'pill marked article-source-state tampered');
      if (read) el('span', '✓', chip, 'article-source-read');
      chip.setAttribute('data-focus', `source-${item.source}`);
      chip.setAttribute('aria-label', caption); chip.setAttribute('title', caption);
      chip.type = 'button'; chip.setAttribute('aria-pressed', String(item.source === sourceName));
      listen(chip, 'click', () => { pinned = true; sourceName = item.source; render(); }, dynamic);
    }
    const scroll = body.querySelector('.article-text')?.scrollTop || 0;
    body.replaceChildren();
    // Each column's head: the version, the claim it makes, what the world
    // serves now and what the scripted reader last received.
    const heads = el('div', undefined, body, 'article-heads');
    for (const [kind, claim] of [['real', topic.true_claim], ['tampered', topic.false_claim]]) {
      const head = el('div', undefined, heads, `article-head ${kind}`);
      const top = el('div', undefined, head, 'article-head-top');
      el('h2', kind === 'real' ? 'Real' : 'Tampered', top);
      if (source.served === kind) el('span', 'Served now', top, 'pill outline article-served');
      const statement = el('p', undefined, head, 'article-claim');
      el('span', kind === 'real' ? 'True claim' : 'False claim', statement, 'article-kicker');
      statement.append(` ${claim}`);
      if (last?.fields.served === kind) {
        readMarker.replaceChildren();
        el('span', `✓ Read by ${reader}`, readMarker, 'article-read-name');
        el('span', `Revision ${last.fields.tamper_revision} · at ${time(last.at)}`, readMarker, 'article-read-detail');
        head.appendChild(readMarker);
        if (last.seq > markedRead) {
          services.moment(readMarker); markedRead = last.seq;
          announce.textContent = `${reader.replace(/^./u, (letter) => letter.toUpperCase())} read the ${kind} version at revision ${last.fields.tamper_revision}.`;
        }
      }
    }
    const mismatch = last && last.fields.tamper_revision !== diff.revision;
    const note = !last ? 'This source has not been read in this run.' : mismatch ? `${readerName} has not read this page since the switch changed.` : 'The last read matches this revision.';
    const callout = el('p', undefined, body, `article-read-note${mismatch ? ' moment' : ''}`);
    el('span', note, callout, mismatch ? 'kind' : undefined);
    const text = el('div', undefined, body, 'article-text');
    text.setAttribute('data-focus', 'article-text');
    text.setAttribute('tabindex', '0'); text.setAttribute('aria-label', 'Both article versions, scroll together');
    for (let index = 0; index < Math.max(source.real.paragraphs.length, source.tampered.paragraphs.length); index++) {
      const row = el('div', undefined, text, 'article-paragraphs');
      for (const kind of ['real', 'tampered']) {
        const paragraph = el('p', undefined, row, kind);
        for (const segment of source[kind].paragraphs[index] || []) {
          el('span', `${segment.text} `, paragraph, segment.changed ? 'changed' : 'unchanged');
        }
      }
    }
    text.scrollTop = scroll;
    history.replaceChildren();
    const real = reads.filter((event) => event.fields.served === 'real').length;
    const changes = events.filter((event) => event.source === 'fakewiki' && event.kind === 'tampering');
    const end = Math.max(services.runTime(), ...reads.map((event) => event.at), ...changes.map((event) => event.at), 0.001);
    const summary = el('div', undefined, history, 'article-history-summary');
    el('p', `${reads.length} ${incomplete ? 'retained ' : ''}${reads.length === 1 ? 'read' : 'reads'}: ${real} real, ${reads.length - real} tampered`, summary, 'article-counts');
    el('p', `${time(0)} – ${time(end)} · ○ real  ● tampered  ┆ switch`, summary, 'article-meta');
    const axis = el('div', undefined, history, 'article-axis');
    const marks = [...reads, ...changes].sort((a, b) => a.seq - b.seq);
    const width = Math.max((axis.clientWidth || 0) - 24, 120);
    const positions = spread(marks.map((event) => Math.min(event.at / end, 1)), width);
    for (const [index, event] of marks.entries()) {
      const read = isRead(event), kind = read ? event.fields.served : 'switch';
      const caption = read
        ? `Read of the ${kind} version, revision ${event.fields.tamper_revision}, at ${time(event.at)}`
        : `Switch ${event.fields.on ? 'on' : 'off'}, revision ${event.fields.revision}${event.fields.changed ? '' : ' (unchanged)'}, at ${time(event.at)}`;
      const mark = el('button', undefined, axis, `article-tick ${kind}`);
      mark.setAttribute('data-focus', `event-${event.seq}`);
      mark.type = 'button'; mark.setAttribute('title', caption); mark.setAttribute('aria-label', caption);
      mark.style.setProperty('left', `calc((100% - 24px) * ${positions[index].toFixed(4)} + 12px)`);
      listen(mark, 'click', () => services.selection.set({ host: event.sandbox?.name || null, node: event.node || null, event, connection: event.conn ?? null, request: event.fields?.request_id ?? null, links: [] }), dynamic);
    }
    if (focusKey) [...panel.querySelectorAll('[data-focus]')].find((node) => node.getAttribute('data-focus') === focusKey)?.focus();
    loss.textContent = incomplete ? 'History is incomplete; counts and marks cover retained observations only.' : '';
  }
  listen(follow, 'click', () => { pinned = false; render(); });
  listen(toggle, 'click', async () => {
    if (busy || !state || disposed) return;
    busy = true; switchState(); reply.textContent = 'Waiting for the world…'; reply.dataset.kind = 'pending';
    try {
      const result = await services.transport.post('/api/command/tamper', { request_id: crypto.randomUUID(), command: { type: 'set_tampering', on: !state.on, expected_revision: state.revision } }, controller.signal);
      if (disposed) return;
      reply.textContent = result.status === 'pending' ? 'Command pending. It may still apply; no automatic retry.' : '';
      reply.dataset.kind = 'pending';
    } catch (error) {
      if (disposed) return;
      const rejected = error.body?.rejection;
      reply.textContent = rejected?.reason === 'stale_revision' ? `The switch changed elsewhere. Current revision ${rejected.current}. No retry was sent.` : `Command not confirmed: ${error.message}. No automatic retry.`;
      reply.dataset.kind = 'rejected';
    } finally { if (!disposed) { busy = false; switchState(); } }
  });
  switchState();
  cleanup.push(services.state('/api/state/tamper', ({ value }) => { if (!disposed) { state = value; switchState(); } }, (error) => { state = undefined; switchState(); reply.textContent = error.message; reply.dataset.kind = 'rejected'; }));
  cleanup.push(services.state('/api/state/diff', ({ value }) => { diff = value; render(); }, (error) => { loss.textContent = error.message; }));
  cleanup.push(services.state(options.state || '/api/state/article', ({ value }) => {
    if (value) { hosts = value.hosts; reader = value.reader; readerHost = value.reader_host; render(); }
  }, (error) => { loss.textContent = `Addresses unavailable: ${error.message}`; }));
  const watch = services.watch();
  function ingest(incoming, status) {
    const wasIncomplete = incomplete;
    if (incoming.some((event) => event.source === 'events' && event.kind === 'dropped')) incomplete = true;
    if (status?.incomplete || status?.losses?.some((item) => item.stream === 'events' && item.count)) incomplete = true;
    const collected = new Map(events.map((event) => [event.seq, event]));
    let changed = false;
    for (const event of incoming) {
      if ((isRead(event) || (event.source === 'fakewiki' && event.kind === 'tampering')) && !collected.has(event.seq)) {
        collected.set(event.seq, event); changed = true;
      }
    }
    events = [...collected.values()].sort((a, b) => a.seq - b.seq);
    if (events.length > LIMIT) { incomplete = true; events = events.slice(-LIMIT); }
    if (changed || wasIncomplete !== incomplete) render();
  }
  let loadingHistory = false;
  const cursors = new Map(['/api/event-table/reads-scripted-reader', '/api/event-table/tamper-applied'].map((path) => [path, 0]));
  async function backfill() {
    if (loadingHistory || disposed) return;
    loadingHistory = true;
    try {
      for (const [path, cursor] of cursors) {
        let after = cursor;
        while (!disposed) {
          const value = await services.transport.get(path, { after }, controller.signal);
          if (disposed) return;
          ingest(value.rows || [], { incomplete: Boolean(value.dropped) });
          if (value.next <= after) break;
          after = value.next;
          cursors.set(path, after);
        }
      }
    } catch (error) { if (!disposed) { incomplete = true; loss.textContent = `History unavailable: ${error.message}`; } }
    finally { loadingHistory = false; }
  }
  listen(watch, 'snapshot', (event) => { const value = JSON.parse(event.data); ingest(value.events || [], value.status); void backfill(); });
  listen(watch, 'event', (event) => ingest([JSON.parse(event.data)]));
  listen(watch, 'status', (event) => ingest([], JSON.parse(event.data).status));
  listen(watch, 'error', () => { loss.textContent = 'Read stream disconnected. Last observed read is shown.'; });
  return () => { disposed = true; controller.abort(); cleanup.splice(0).forEach((off) => off()); dynamic.splice(0).forEach((off) => off()); watch.close(); root.classList.remove('article-container'); root.replaceChildren(); };
}
