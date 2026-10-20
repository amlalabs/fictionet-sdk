// Article text and delivery facts come from separate world projections.
export function mount(root, services, options = {}) {
  const { reconcile } = services.dom;
  const el = (tag, text, parent, cls) => {
    const node = root.ownerDocument.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (cls) node.setAttribute('class', cls);
    parent?.appendChild(node);
    return node;
  };
  root.classList.add('article-container');
  const cleanup = [];
  const listen = (target, type, fn) => {
    target.addEventListener(type, fn);
    cleanup.push(() => target.removeEventListener(type, fn));
  };
  // Buttons in kept lists hold their own listener, released on dispose.
  const button = (cls, onClick) => {
    const node = el('button', undefined, undefined, cls);
    node.type = 'button';
    node.addEventListener('click', onClick);
    return { node, off: () => node.removeEventListener('click', onClick) };
  };
  const topicButtons = new Map(), chipButtons = new Map(), ticks = new Map();
  const controller = new AbortController();
  const sheet = el('link', undefined, root);
  sheet.setAttribute('rel', 'stylesheet'); sheet.setAttribute('href', '/assets/article.css');
  const panel = el('div', undefined, root, 'article-panel');
  const address = el('div', undefined, panel, 'article-address');
  const url = el('div', 'Waiting for the article…', address, 'article-url');
  const identity = el('p', '', address, 'article-meta');
  const switchRow = el('div', undefined, panel, 'article-switch-row');
  const toggle = el('button', undefined, switchRow, 'article-switch');
  const track = el('span', undefined, toggle, 'article-switch-track');
  track.setAttribute('aria-hidden', 'true');
  el('span', undefined, track, 'article-switch-knob');
  const switchLabel = el('span', 'Waiting for state…', toggle, 'article-switch-label');
  toggle.type = 'button'; toggle.setAttribute('role', 'switch'); toggle.setAttribute('aria-label', 'Tamper');
  const revision = el('p', '', switchRow, 'article-meta');
  const reply = el('p', '', panel, 'article-reply'); reply.setAttribute('role', 'status');
  const pickers = el('div', undefined, panel, 'article-pickers');
  const topicRow = el('div', undefined, pickers, 'article-topic-row');
  const topics = el('div', undefined, topicRow, 'article-topics segmented');
  topics.setAttribute('role', 'group'); topics.setAttribute('aria-label', 'Topic');
  const chips = el('div', undefined, pickers, 'article-chips');
  chips.setAttribute('role', 'group'); chips.setAttribute('aria-label', 'Source');
  const follow = el('button', 'Following reads', topicRow, 'text-button'); follow.type = 'button';
  const body = el('div', undefined, panel, 'article-body');
  const history = el('div', undefined, panel, 'article-history');
  history.hidden = true;
  const counts = el('p', '', el('div', undefined, history, 'article-history-summary'), 'article-counts');
  const axis = el('div', undefined, history, 'article-axis');
  const span = el('div', '', history, 'article-meta');
  const loss = el('p', '', panel, 'article-meta'); loss.setAttribute('role', 'status');
  const readMarker = el('p', '', undefined, 'article-read');
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
    switchLabel.textContent = busy ? 'Changing…' : state?.on ? 'Serving the tampered article' : 'Serving the real article';
    revision.textContent = state ? `${state.scope === 'wikipedia' ? 'Wikipedia only · ' : state.scope === 'all_sources' ? 'All sources · ' : ''}Revision ${state.revision} · ${state.revision ? 'last changed' : 'initial state'} ${time(seconds(state.since_start))}` : 'Waiting for the world';
  }
  function render() {
    if (disposed || !diff) return;
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
    const parsed = new URL(source.url);
    url.textContent = last ? `${last.fields.scheme}://${last.fields.host}${last.fields.path}${last.fields.query ? `?${last.fields.query}` : ''}` : source.url;
    identity.textContent = `${hosts[parsed.hostname] || 'Address loading'} · same host, address and certificate for both versions`;
    url.setAttribute('title', url.textContent);
    identity.setAttribute('title', identity.textContent);
    address.setAttribute('title', `${url.textContent} · ${identity.textContent}${last ? '' : ' · Not read yet'}`);
    panel.dataset.on = String(diff.on);
    follow.textContent = pinned ? 'Follow latest read' : 'Following reads';
    // Topic and source buttons keep their elements, so focus stays put.
    reconcile(topics, diff.topics, (item) => item.topic, (item) => button(undefined, () => { pinned = true; topicName = item.topic; sourceName = undefined; render(); }), (entry, item) => {
      const title = item.sources.find((source) => new URL(source.url).hostname === 'en.wikipedia.org')?.real.title || item.topic;
      if (entry.node.textContent !== title) { entry.node.textContent = title; entry.node.setAttribute('title', title); }
      entry.node.setAttribute('aria-pressed', String(item.topic === topicName));
    }, topicButtons);
    reconcile(chips, topic.sources, (item) => item.source, (item) => button(undefined, () => { pinned = true; sourceName = item.source; render(); }), (entry, item) => {
      const read = readsFor(topicName, item.source).length > 0;
      const host = new URL(item.url).hostname;
      const caption = `${host} · ${item.served} · ${read ? 'read' : 'unread'}`;
      if (entry.caption !== caption) {
        entry.caption = caption;
        entry.node.replaceChildren();
        el('span', host, entry.node, 'article-source-host');
        el('span', item.served === 'real' ? 'Real' : 'Tampered', entry.node, `article-source-state ${item.served}`);
        if (read) el('span', '✓ read', entry.node, 'article-source-read');
        entry.node.setAttribute('aria-label', caption); entry.node.setAttribute('title', caption);
      }
      entry.node.setAttribute('aria-pressed', String(item.source === sourceName));
    }, chipButtons);
    const scroll = body.querySelector('.article-text')?.scrollTop || 0;
    body.replaceChildren();
    const claims = el('div', undefined, body, 'article-claims');
    for (const [kind, claim] of [['real', topic.true_claim], ['tampered', topic.false_claim]]) {
      const box = el('div', undefined, claims, `article-claim ${kind}`);
      el('span', kind === 'real' ? 'THE TRUE CLAIM' : 'THE FALSE CLAIM', box, 'article-kicker');
      el('p', claim, box);
    }
    const heads = el('div', undefined, body, 'article-heads');
    for (const kind of ['real', 'tampered']) {
      const head = el('div', undefined, heads, `article-head ${kind}`);
      el('h2', kind === 'real' ? 'Real' : 'Tampered', head);
      if (source.served === kind) el('span', 'Served now', head, 'article-served');
      if (last?.fields.served === kind) {
        readMarker.textContent = `✓ Read by ${reader} · r${last.fields.tamper_revision} · ${time(last.at)}`;
        head.appendChild(readMarker);
        if (last.seq > markedRead) { services.moment(readMarker); markedRead = last.seq; }
      }
    }
    const mismatch = last && last.fields.tamper_revision !== diff.revision;
    const readerName = reader.replace(/ \(scripted\)$/, '').replace(/^./u, (letter) => letter.toUpperCase());
    const note = !last ? 'This source has not been read in this run.' : mismatch ? `${readerName} has not read this page since the switch changed.` : 'The last read matches this revision.';
    const callout = el('p', undefined, body, `article-read-note${mismatch ? ' moment' : ''}`);
    el('span', note, callout, mismatch ? 'kind' : undefined);
    const text = el('div', undefined, body, 'article-text');
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
    history.hidden = false;
    const real = reads.filter((event) => event.fields.served === 'real').length;
    counts.textContent = `${reads.length} ${incomplete ? 'retained ' : ''}${reads.length === 1 ? 'read' : 'reads'}: ${real} real, ${reads.length - real} tampered`;
    const changes = events.filter((event) => event.source === 'fakewiki' && event.kind === 'tampering');
    const end = Math.max(services.runTime(), ...reads.map((event) => event.at), ...changes.map((event) => event.at), 0.001);
    reconcile(axis, [...reads, ...changes].sort((a, b) => a.seq - b.seq), (event) => event.seq, (event) => {
      const read = isRead(event), kind = read ? event.fields.served : 'switch';
      const caption = read ? `${kind} · r${event.fields.tamper_revision} · ${time(event.at)}` : `${event.fields.on ? 'On' : 'Off'} r${event.fields.revision}${event.fields.changed ? '' : ' unchanged'}`;
      const mark = button(`article-tick ${kind}`, () => services.selection.set({ host: event.sandbox?.name || null, node: event.node || null, event, connection: event.conn ?? null, request: event.fields?.request_id ?? null, links: [] }));
      if (!read) el('span', caption, mark.node);
      mark.node.setAttribute('title', caption); mark.node.setAttribute('aria-label', caption);
      return { ...mark, read };
    }, (mark, event) => {
      if (!mark.read) mark.node.dataset.end = String(event.at / end > 0.5);
      mark.node.style.setProperty('left', `calc(${event.at / end * 100}% + ${12 - event.at / end * 24}px)`);
    }, ticks);
    span.textContent = `${time(0)} – ${time(end)} · ○ real  ● tampered`;
    loss.textContent = incomplete ? 'History is incomplete; counts and marks cover retained observations only.' : '';
  }
  listen(follow, 'click', () => { pinned = false; render(); });
  listen(toggle, 'click', async () => {
    if (busy || !state || disposed) return;
    busy = true; switchState(); reply.textContent = 'Waiting for the world…';
    try {
      const result = await services.transport.post('/api/command/tamper', { request_id: crypto.randomUUID(), command: { type: 'set_tampering', on: !state.on, expected_revision: state.revision } }, controller.signal);
      if (disposed) return;
      reply.textContent = result.status === 'pending' ? 'Command pending. It may still apply; no automatic retry.' : '';
    } catch (error) {
      if (disposed) return;
      const rejected = error.body?.rejection;
      reply.textContent = rejected?.reason === 'stale_revision' ? `The switch changed elsewhere. Current revision ${rejected.current}. No retry was sent.` : `Command not confirmed: ${error.message}. No automatic retry.`;
    } finally { if (!disposed) { busy = false; switchState(); } }
  });
  switchState();
  cleanup.push(services.state('/api/state/tamper', ({ value }) => { if (!disposed) { state = value; switchState(); } }, (error) => { state = undefined; switchState(); reply.textContent = error.message; }));
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
  return () => {
    disposed = true; controller.abort(); cleanup.splice(0).forEach((off) => off());
    for (const kept of [topicButtons, chipButtons, ticks]) kept.forEach((entry) => entry.off());
    watch.close(); root.classList.remove('article-container'); root.replaceChildren();
  };
}
