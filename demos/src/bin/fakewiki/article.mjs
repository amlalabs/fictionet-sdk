// Article text and delivery facts come from separate world projections.
export function mount(root, services, options = {}) {
  const { el } = services.dom.scoped(root);
  const { listen } = services.dom;
  root.classList.add('article-container');
  const cleanup = [], dynamic = [];
  const controller = new AbortController();
  const sheet = el('link', {}, root);
  sheet.setAttribute('rel', 'stylesheet'); sheet.setAttribute('href', '/assets/article.css');
  const panel = el('div', { class: 'article-panel' }, root);
  const switchRow = el('div', { class: 'article-switch-row' }, panel);
  const toggle = el('button', { class: 'switch article-switch' }, switchRow);
  const track = el('span', { class: 'switch-track' }, toggle);
  track.setAttribute('aria-hidden', 'true');
  el('span', { class: 'switch-knob' }, track);
  const switchLabel = el('span', { class: 'article-switch-label', text: 'Waiting for state…' }, toggle);
  toggle.type = 'button'; toggle.setAttribute('role', 'switch'); toggle.setAttribute('aria-label', 'Tamper');
  const revision = el('p', { class: 'article-meta' }, switchRow);
  const reply = el('p', { class: 'article-reply' }, panel); reply.setAttribute('role', 'status');
  const address = el('div', { class: 'article-address' }, panel);
  const where = el('div', { class: 'article-where' }, address);
  const url = el('div', { class: 'article-url', text: 'Waiting for the article…' }, where);
  const identity = el('p', { class: 'article-meta' }, where);
  const follow = el('button', { class: 'text-button', text: 'Following reads' }, address); follow.type = 'button';
  address.hidden = true;
  const pickers = el('div', { class: 'article-pickers' }, panel);
  pickers.hidden = true;
  const topics = el('div', { class: 'article-topics segmented' }, pickers);
  topics.setAttribute('role', 'group'); topics.setAttribute('aria-label', 'Topic');
  const chips = el('div', { class: 'article-chips' }, pickers);
  chips.setAttribute('role', 'group'); chips.setAttribute('aria-label', 'Source');
  const body = el('div', { class: 'article-body' }, panel);
  const loading = el('div', { class: 'article-loading' }, body);
  loading.setAttribute('role', 'status');
  el('strong', { text: 'Waiting for the article versions' }, loading);
  el('p', { text: 'The world has not published the article yet. The real and tampered versions appear here when it does.' }, loading);
  const history = el('div', { class: 'article-history' }, panel);
  history.setAttribute('role', 'group'); history.setAttribute('aria-label', 'Reads and switch changes in this run');
  history.hidden = true;
  const loss = el('p', { class: 'article-meta article-loss' }, panel); loss.setAttribute('role', 'status');
  // New reads are announced once here; the visible marker moves between renders.
  const announce = el('p', { class: 'article-announce' }, panel); announce.setAttribute('aria-live', 'polite');
  const readMarker = el('div', { class: 'article-read' }, undefined);
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
      const button = el('button', { text: title }, topics);
      button.setAttribute('title', title); button.setAttribute('data-focus', `topic-${item.topic}`);
      button.type = 'button'; button.setAttribute('aria-pressed', String(item.topic === topicName));
      dynamic.push(listen(button, 'click', () => { pinned = true; topicName = item.topic; sourceName = undefined; render(); }));
    }
    chips.replaceChildren();
    for (const item of topic.sources) {
      const read = readsFor(topicName, item.source).length > 0;
      const host = new URL(item.url).hostname;
      const caption = `${host} · ${item.served} · ${read ? 'read' : 'unread'}`;
      const chip = el('button', {}, chips);
      el('span', { class: 'article-source-host', text: host }, chip);
      if (item.served === 'tampered') el('span', { class: 'pill marked article-source-state tampered', text: 'Tampered' }, chip);
      if (read) el('span', { class: 'article-source-read', text: '✓' }, chip);
      chip.setAttribute('data-focus', `source-${item.source}`);
      chip.setAttribute('aria-label', caption); chip.setAttribute('title', caption);
      chip.type = 'button'; chip.setAttribute('aria-pressed', String(item.source === sourceName));
      dynamic.push(listen(chip, 'click', () => { pinned = true; sourceName = item.source; render(); }));
    }
    const scroll = body.querySelector('.article-text')?.scrollTop || 0;
    body.replaceChildren();
    // Each column's head: the version, the claim it makes, what the world
    // serves now and what the scripted reader last received.
    const heads = el('div', { class: 'article-heads' }, body);
    for (const [kind, claim] of [['real', topic.true_claim], ['tampered', topic.false_claim]]) {
      const head = el('div', { class: `article-head ${kind}` }, heads);
      const top = el('div', { class: 'article-head-top' }, head);
      el('h2', { text: kind === 'real' ? 'Real' : 'Tampered' }, top);
      if (source.served === kind) el('span', { class: 'pill outline article-served', text: 'Served now' }, top);
      const statement = el('p', { class: 'article-claim' }, head);
      el('span', { class: 'article-kicker', text: kind === 'real' ? 'True claim' : 'False claim' }, statement);
      statement.append(` ${claim}`);
      if (last?.fields.served === kind) {
        readMarker.replaceChildren();
        el('span', { class: 'article-read-name', text: `✓ Read by ${reader}` }, readMarker);
        el('span', { class: 'article-read-detail', text: `Revision ${last.fields.tamper_revision} · at ${time(last.at)}` }, readMarker);
        head.appendChild(readMarker);
        if (last.seq > markedRead) {
          services.moment(readMarker); markedRead = last.seq;
          announce.textContent = `${reader.replace(/^./u, (letter) => letter.toUpperCase())} read the ${kind} version at revision ${last.fields.tamper_revision}.`;
        }
      }
    }
    const mismatch = last && last.fields.tamper_revision !== diff.revision;
    const note = !last ? 'This source has not been read in this run.' : mismatch ? `${readerName} has not read this page since the switch changed.` : 'The last read matches this revision.';
    const callout = el('p', { class: `article-read-note${mismatch ? ' moment' : ''}` }, body);
    el('span', mismatch ? { class: 'kind', text: note } : { text: note }, callout);
    const text = el('div', { class: 'article-text' }, body);
    text.setAttribute('data-focus', 'article-text');
    text.setAttribute('tabindex', '0'); text.setAttribute('aria-label', 'Both article versions, scroll together');
    for (let index = 0; index < Math.max(source.real.paragraphs.length, source.tampered.paragraphs.length); index++) {
      const row = el('div', { class: 'article-paragraphs' }, text);
      for (const kind of ['real', 'tampered']) {
        const paragraph = el('p', { class: kind }, row);
        for (const segment of source[kind].paragraphs[index] || []) {
          el('span', { class: segment.changed ? 'changed' : 'unchanged', text: `${segment.text} ` }, paragraph);
        }
      }
    }
    text.scrollTop = scroll;
    history.replaceChildren();
    const real = reads.filter((event) => event.fields.served === 'real').length;
    const changes = events.filter((event) => event.source === 'fakewiki' && event.kind === 'tampering');
    const end = Math.max(services.runTime(), ...reads.map((event) => event.at), ...changes.map((event) => event.at), 0.001);
    const summary = el('div', { class: 'article-history-summary' }, history);
    el('p', { class: 'article-counts', text: `${reads.length} ${incomplete ? 'retained ' : ''}${reads.length === 1 ? 'read' : 'reads'}: ${real} real, ${reads.length - real} tampered` }, summary);
    el('p', { class: 'article-meta', text: `${time(0)} – ${time(end)} · ○ real  ● tampered  ┆ switch` }, summary);
    const axis = el('div', { class: 'article-axis' }, history);
    const marks = [...reads, ...changes].sort((a, b) => a.seq - b.seq);
    const width = Math.max((axis.clientWidth || 0) - 24, 120);
    const positions = spread(marks.map((event) => Math.min(event.at / end, 1)), width);
    for (const [index, event] of marks.entries()) {
      const read = isRead(event), kind = read ? event.fields.served : 'switch';
      const caption = read
        ? `Read of the ${kind} version, revision ${event.fields.tamper_revision}, at ${time(event.at)}`
        : `Switch ${event.fields.on ? 'on' : 'off'}, revision ${event.fields.revision}${event.fields.changed ? '' : ' (unchanged)'}, at ${time(event.at)}`;
      const mark = el('button', { class: `article-tick ${kind}` }, axis);
      mark.setAttribute('data-focus', `event-${event.seq}`);
      mark.type = 'button'; mark.setAttribute('title', caption); mark.setAttribute('aria-label', caption);
      mark.style.setProperty('left', `calc((100% - 24px) * ${positions[index].toFixed(4)} + 12px)`);
      dynamic.push(listen(mark, 'click', () => services.selection.set({ host: event.sandbox?.name || null, node: event.node || null, event, connection: event.conn ?? null, request: event.fields?.request_id ?? null, links: [] })));
    }
    if (focusKey) [...panel.querySelectorAll('[data-focus]')].find((node) => node.getAttribute('data-focus') === focusKey)?.focus();
    loss.textContent = incomplete ? 'History is incomplete; counts and marks cover retained observations only.' : '';
  }
  cleanup.push(listen(follow, 'click', () => { pinned = false; render(); }));
  cleanup.push(listen(toggle, 'click', async () => {
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
  }));
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
  cleanup.push(listen(watch, 'snapshot', (event) => { const value = JSON.parse(event.data); ingest(value.events || [], value.status); void backfill(); }));
  cleanup.push(listen(watch, 'event', (event) => ingest([JSON.parse(event.data)])));
  cleanup.push(listen(watch, 'status', (event) => ingest([], JSON.parse(event.data).status)));
  cleanup.push(listen(watch, 'error', () => { loss.textContent = 'Read stream disconnected. Last observed read is shown.'; }));
  return () => { disposed = true; controller.abort(); cleanup.splice(0).forEach((off) => off()); dynamic.splice(0).forEach((off) => off()); watch.close(); root.classList.remove('article-container'); root.replaceChildren(); };
}
