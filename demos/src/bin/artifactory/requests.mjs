// Requests: every HTTP request row the world kept, with its classification
// as a badge. Selecting a row selects its request and connection, so Events
// shows that connection and Packets can show its address pair.
import { FAMILIES, builder, credential, words, topics } from './common.mjs';

const TRAFFIC = { setup: 'setup', other: 'other', after: 'after' };

export function statusText(outcome) {
  if (!outcome) return '—';
  const text = [outcome.status, words(outcome.kind)].filter((part) => part != null && part !== '').join(' ');
  return outcome.complete === false ? `${text}, cut off` : text;
}

export function mount(root, services, options) {
  const { reconcile } = services.dom;
  const fmt = services.format, { plural } = fmt;
  const b = builder(root, services.dom);
  const { el, on, button, set } = b;
  b.stylesheet();
  const panel = el('div', { class: 'art-panel requests-panel' }, root);
  const head = el('div', { class: 'art-head' }, panel);
  el('h2', { text: 'Requests to the world’s sites' }, head);
  el('p', { class: 'note', text: 'Every HTTP request the world answered or refused, oldest first. Select one to follow its connection.' }, head);
  const legend = el('ul', { class: 'requests-legend' }, panel);
  legend.setAttribute('aria-label', 'Classification colors');
  for (const [family, label] of FAMILIES) el('span', { class: `pill family-${family}`, text: label }, el('li', {}, legend));
  const status = el('p', { class: 'loss-note', text: 'Loading requests…' }, panel);
  status.setAttribute('role', 'status');
  const scroll = el('div', { class: 'requests-scroll' }, panel);
  const table = el('table', { class: 'data-table requests-table' }, scroll);
  const tr = el('tr', {}, el('thead', {}, table));
  for (const [label, cls] of [['Time', 'numeric'], ['Step', ''], ['Class', ''], ['Method', ''], ['Host', ''], ['Path', ''], ['Status', ''], ['Package', ''], ['Credential', ''], ['SSRF', 'numeric']]) {
    el('th', { class: cls, text: label }, tr).setAttribute('scope', 'col');
  }
  const body = el('tbody', {}, table);
  const empty = el('tbody', {}, table);
  const emptyCell = el('td', { class: 'empty-cell', text: 'No requests yet. They appear as the story runs.' }, el('tr', {}, empty));
  emptyCell.setAttribute('colspan', '10');
  const detail = el('section', { class: 'requests-detail section' }, panel);
  detail.hidden = true;
  const detailTitle = el('h3', { class: 'mono' }, detail);
  const detailList = el('dl', { class: 'kv requests-kv' }, detail);
  const actions = el('p', { class: 'requests-actions' }, detail);
  const events = button(actions, 'button', 'Events on this connection', () => services.showPanel('events'));
  const packets = button(actions, 'button', 'Packets for this address pair', () => {
    const row = selectedRow();
    if (row?.local && row?.peer) services.showPackets?.({ local: row.local, peer: row.peer });
  });
  el('span', { class: 'note', text: 'The address pair can match other connections between the same ports.' }, actions);

  const rows = new Map();
  let latest = {}, selected = services.selection.get().request ?? null, disposed = false, scrolled = null;
  const selectedRow = () => (latest.requests?.rows || []).find((tag) => tag.row.seq === selected)?.row || null;

  function stepLabel(tag, story, hosts) {
    const label = tag.traffic !== 'agent' ? TRAFFIC[tag.traffic] || words(tag.traffic) : (() => {
      const index = story.findIndex((step) => step.title === tag.step);
      return index < 0 ? tag.step : String(index + 1);
    })();
    // With two workstations, the step says which one sent the request.
    return hosts && tag.row.sandbox ? `${tag.row.sandbox} · ${label}` : label;
  }

  function choose(tag) {
    if (selected === tag.row.seq) services.selection.set({ request: null, connection: null });
    else services.selection.set({ request: tag.row.seq, connection: tag.row.conn ?? null, event: null, links: [], node: null });
  }

  function renderDetail() {
    const tag = (latest.requests?.rows || []).find((item) => item.row.seq === selected);
    detail.hidden = !tag;
    if (!tag) return;
    const row = tag.row;
    set(detailTitle, `${row.method} ${row.host ?? '(no host)'}${row.path}`);
    detailList.replaceChildren();
    const add = (key, value) => {
      if (value === null || value === undefined || value === '') return;
      el('dt', { text: key }, detailList);
      el('dd', { class: 'mono', text: String(value) }, detailList);
    };
    add('Time', fmt.fmtRunTime(tag.at));
    add('Step', tag.traffic === 'agent' ? tag.step : `${words(tag.traffic)} traffic`);
    add('Classification', `${words(row.classification)} (${FAMILIES.find(([id]) => id === row.family)?.[1] || row.family})`);
    add('Repository', row.repo);
    add('Package', row.package && [row.package.project, row.package.role && words(row.package.role), row.package.filename].filter(Boolean).join(' · '));
    add('Upstream named', row.upstream && `${row.upstream} (never fetched)`);
    add('Off-site targets', `${row.ssrf_targets}${row.techniques?.length ? ` in ${row.techniques.map(words).join(', ')}` : ''}${row.scan_complete ? '' : ', scan incomplete'}`);
    add('Credential', credential(row.credential));
    add('Folder revision', row.folder_revision);
    add('Answer', `${statusText(row.outcome)}${row.outcome?.sent != null ? `, ${fmt.fmtBytes(row.outcome.sent)} sent` : ''}`);
    add('Connection', row.conn);
    add('World address', row.local);
    add('Guest address', row.peer);
    events.disabled = row.conn == null;
    packets.disabled = !(row.local && row.peer && services.showPackets);
  }

  function render() {
    const tags = latest.requests?.rows || [];
    const story = latest.doors?.story || [];
    const hosts = new Set(tags.map((tag) => tag.row.sandbox).filter(Boolean)).size > 1;
    empty.hidden = tags.length > 0;
    reconcile(body, tags, (tag) => tag.row.seq, (tag) => {
      const node = on(el('tr', { class: 'requests-row' }), 'click', () => choose(tag));
      node.setAttribute('tabindex', '0');
      on(node, 'keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault?.(); choose(tag); } });
      const row = tag.row;
      const cells = {};
      cells.time = el('td', { class: 'mono numeric', text: fmt.fmtRunTime(tag.at) }, node);
      cells.step = el('td', { class: `mono requests-step traffic-${tag.traffic}` }, node);
      el('span', { class: `pill family-${row.family}`, text: words(row.classification) }, el('td', {}, node));
      el('td', { class: 'mono', text: row.method }, node);
      el('td', { class: 'mono requests-host', text: row.host ?? '(no host)' }, node).setAttribute('title', row.host ?? '');
      el('td', { class: 'mono requests-path', text: row.path }, node).setAttribute('title', row.path);
      el('td', { class: `requests-status outcome-${row.outcome?.kind}`, text: statusText(row.outcome) }, node);
      const pkg = el('td', { class: 'mono' }, node);
      if (row.package) el('span', { class: row.package.role === 'lookalike' ? 'pill marked' : '', text: row.package.project }, pkg);
      const chip = el('td', {}, node);
      if (row.credential) el('span', { class: 'pill outline', text: credential(row.credential) }, chip);
      el('td', { class: 'mono numeric', text: row.scan_complete ? String(row.ssrf_targets) : `${row.ssrf_targets}+` }, node).setAttribute('title', row.scan_complete ? 'Off-site targets found' : 'The scan was incomplete');
      return { node, cells };
    }, (entry, tag, fresh) => {
      set(entry.cells.step, stepLabel(tag, story, hosts));
      entry.cells.step.setAttribute('title', tag.traffic === 'agent' ? tag.step : `${words(tag.traffic)} traffic`);
      if (fresh) entry.node.classList.add('new-row');
      if (services.isMoment?.({ seq: tag.row.seq })) services.moment(entry.node);
      const chosen = tag.row.seq === selected;
      entry.node.classList.toggle('on', chosen);
      entry.node.setAttribute('aria-selected', String(chosen));
    }, rows);
    if (selected != null && scrolled !== selected && rows.has(selected)) {
      scrolled = selected;
      rows.get(selected).node.scrollIntoView?.({ block: 'nearest' });
    }
    renderDetail();
  }

  const stopTopics = topics(services, { requests: options.state, doors: '/api/state/doors-tried' }, (values, statuses) => {
    if (disposed) return;
    latest = values;
    const requests = values.requests;
    if (!requests) { set(status, 'Waiting for the first publication.'); return; }
    const notes = [];
    if (requests.dropped) notes.push(`${plural(requests.dropped, 'older row')} dropped. The page keeps the latest ${requests.rows.length}.`);
    if (requests.lost) notes.push(`${plural(requests.lost, 'observation')} lost before the page saw ${requests.lost === 1 ? 'it' : 'them'}.`);
    if (statuses.requests?.too_large) notes.push('A publication exceeded its byte bound; the last complete rows are shown.');
    set(status, notes.join(' '));
    render();
  }, (name, error) => { if (!disposed) set(status, `Could not load ${name}: ${error.message}.`); });
  const stopSelection = services.selection.subscribe((value) => {
    if (disposed || (value.request ?? null) === selected) return;
    selected = value.request ?? null;
    render();
  });
  const stopMoments = services.onMoment?.(() => { if (!disposed) render(); });
  return () => {
    disposed = true;
    stopTopics();
    stopSelection();
    stopMoments?.();
    b.release();
    rows.clear(); latest = {};
    root.replaceChildren();
  };
}
