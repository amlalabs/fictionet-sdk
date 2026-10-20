// The packet drawer: its stream, queue, selection, detail and hex view.
// The caller passes DOM helpers, graph links, labels and orientation, and a fit callback.
import { labelChips, flowMatches } from './components/labels.mjs';
import { listen } from './dom.mjs';

export function createPackets({
  $, el, packetStream, packet, download, getEdge, ends, nodeLabel, fmtCount, fit, maxRows = 3000,
  placeholder = (many) => (many ? 'Packets from all of these links appear here, merged, as they cross. Select one to see its layers.' : 'Packets appear here as they cross the link. Select one to see its layers.'),
  pcapLabel = 'Capture for Wireshark', onDetail = () => {}, stopped = () => null,
  // A table with a Host column gives every row that cell, so gap rows span
  // all nine columns whichever are hidden.
  hostColumn = false,
  // Addresses the page's consoles reach the hosts from. Their packets are
  // the page's own screen and terminal traffic, hidden until shown.
  consoleAddresses = [],
}) {
  // ---------------------------------------------------------------------------
  // The packet drawer

  const cleanup = [];
  const streamCleanup = [];
  const on = (...args) => cleanup.push(listen(...args));
  let stopDrag = () => {};
  const drawer = $('drawer');
  const document = drawer.ownerDocument || globalThis.document;
  const prows = $('prows');
  const plist = $('plist');
  // What the drawer watches: { links: [{ id, flip }], source, paused, held,
  // queue, lastTime, done, skipped, evicted, missed, rows }; done holds links that
  // ended. A packet's side is turned to the drawn edge's:
  // 0 from its first end, 1 from its second.
  let packets = null, labels = [];
  let unread = 0;
  const jump = $('jump-packets');
  const clearUnread = () => { unread = 0; if (jump) jump.hidden = true; };
  if (jump) on(jump, 'click', () => { plist.scrollTop = plist.scrollHeight; clearUnread(); });
  on(plist, 'scroll', () => { if (plist.scrollHeight - plist.scrollTop - plist.clientHeight < 40) clearUnread(); });
  let selection = 0;
  let detailRequest = null;
  /// Rows the packet list keeps.
  const MAX_ROWS = maxRows;
  /// How long a merged packet view holds packets to put them in order.
  const MERGE_HOLD_MS = 400;
  // `10.0.0.2:22` or `[fe80::1]:22` as [address, port]; a bare address has
  // no port.
  const endpoint = (text) => {
    const cut = text.startsWith('[') ? text.indexOf(']') + 1 : text.split(':').length === 2 ? text.indexOf(':') : -1;
    return cut > 0 && text[cut] === ':' ? [text.slice(0, cut), text.slice(cut)] : [text, ''];
  };
  const address = (text) => endpoint(text)[0].replace(/^\[(.*)\]$/, '$1');
  const fromConsole = (p) => consoleAddresses.includes(address(p.src)) || consoleAddresses.includes(address(p.dst));
  let showConsole = false, reopen = null;
  const consoleNote = $('console-note');
  function showConsoleNote() {
    if (!consoleNote || !consoleAddresses.length || !packets) return;
    const where = consoleAddresses.join(', ');
    $('console-text').textContent = showConsole
      ? `Showing console packets · ${where}`
      : `${fmtCount(packets.console)} console ${packets.console === 1 ? 'packet' : 'packets'} hidden · ${where}`;
    consoleNote.title = `The page's own screen and terminal sessions, and the demo's checks, reach the hosts from ${where}.`;
    $('console-toggle').textContent = showConsole ? 'Hide' : 'Show';
    consoleNote.hidden = !showConsole && !packets.console;
  }
  if (consoleNote) {
    on($('console-toggle'), 'click', () => {
      showConsole = !showConsole;
      // The stream replays the history it keeps, now with or without them.
      reopen?.();
    });
  }

  /// Opens the packets of drawn edge `id`: one link, or every link it stands
  /// for, merged.
  function openPackets(id) {
    const d = getEdge(id);
    if (!d) return;
    const [first, second, swapped] = ends(d);
    // The drawer's first direction goes from the sandbox side.
    let members = d.members.map(({ e, flip }) => ({ e, flip: swapped ? !flip : flip }));
    // `fictionet dashboard` merges at most MAX_MERGED links: the busiest.
    const total = members.length;
    if (total > MAX_MERGED) {
      const busy = (m) => m.e.c[0] + m.e.c[2];
      members = members.sort((x, y) => busy(y) - busy(x)).slice(0, MAX_MERGED);
    }
    openLinks(nodeLabel(first), nodeLabel(second), members, d.label, total);
  }

  /// Links one merged packet view may watch, as `fictionet dashboard` allows.
  const MAX_MERGED = 32;

  /// Opens the packets of `members` ({ e, flip }): side 0 of the drawer goes
  /// from `fromName` to `toName`.
  function openLinks(fromName, toName, members, label, total = members.length) {
    closePackets();
    reopen = () => openLinks(fromName, toName, members, label, total);
    clearUnread();
    drawer.hidden = false;
    const many = members.length > 1;
    const count = total > members.length ? `  (the busiest ${members.length} of ${total} links)` : many ? `  (${members.length} links)` : '';
    $('drawer-title').textContent = `${fromName} ↔ ${toName}${label ? `  ${label}` : ''}${count}`;
    $('drawer-title').title = $('drawer-title').textContent;
    $('drawer-title').setAttribute('aria-label', $('drawer-title').textContent);
    $('dir-a').textContent = `${fromName} → ${toName}`;
    $('dir-b').textContent = `${toName} → ${fromName}`;
    const list = members.map((m) => m.e.id).join(',');
    $('pcap-label').textContent = pcapLabel;
    $('pause').textContent = 'Pause';
    $('sampled').hidden = true;
    $('sampled').textContent = '';
    prows.replaceChildren();
    clearDetail(placeholder(many));
    const hosts = new Map(members.filter((m) => m.host).map((m) => [m.e.id, m.host]));
    const showHost = new Set(hosts.values()).size > 1;
    drawer.classList.toggle('merged-hosts', showHost);
    const hostWidth = Math.min(16, Math.max(4, ...[...hosts.values()].map((name) => name.length)));
    drawer.style.setProperty('--packet-host', `calc(${hostWidth}ch + 16px)`);
    const flips = new Map(members.map((m) => [m.e.id, m.flip]));
    const onStream = (...args) => streamCleanup.push(listen(source, ...args));
    const source = packetStream(list, () => {
      if (packets?.source !== source) return;
      invalidateSelection();
      // A new subscription replays retained history, possibly with restarted
      // sequence numbers. Replace its state before accepting any replay.
      packets = { ...packets, rows: 0, held: [], queue: [], lastTime: new Map(), done: new Set(), skipped: 0, evicted: 0, missed: 0, open: members.length, failed: false };
      prows.replaceChildren();
      addGap('Packet history reloaded after reconnect.');
      $('sampled').hidden = true;
      $('sampled').textContent = '';
      clearDetail('Packet history reloaded after reconnect. Select a packet to see its layers.');
    });
    packets = { list, flips, hosts, showHost, widths: { time: 6, src: 6, dst: 9, proto: 6 }, many, source, rows: 0, console: 0, paused: false, held: [], queue: [], lastTime: new Map(), done: new Set(), skipped: 0, evicted: 0, missed: 0, open: members.length, failed: false };
    showConsoleNote();
    onStream('packet', (ev) => {
      const p = JSON.parse(ev.data);
      if (!packets || packets.source !== source) return;
      p.link = p.link || list;
      packets.lastTime.set(p.link, p.t);
      if (flips.get(p.link)) p.side = 1 - p.side;
      // Keep capture loss visible even if its row leaves the browser's queue.
      if (p.evicted > 0) {
        packets.evicted += p.evicted;
        showCounts();
      }
      queueEntry(p);
    });
    onStream('packet_gap', (ev) => {
      if (packets?.source !== source) return;
      const gap = JSON.parse(ev.data);
      packets.missed += gap.missed;
      showCounts();
      const link = gap.link || list;
      // Equal times keep arrival order, so a gap follows this link's last row.
      queueEntry({
        t: packets.lastTime.get(link) ?? 0,
        gap: `Packets ${gap.after + 1}–${gap.next - 1} of link ${link} are no longer kept (${fmtCount(gap.missed)} rows missed).`,
      });
    });
    onStream('link_end', (ev) => {
      if (packets?.source !== source) return;
      packets.open--;
      packets.done.add(JSON.parse(ev.data).link);
    });
    onStream('link_error', (ev) => {
      if (packets?.source !== source) return;
      const { link, error } = JSON.parse(ev.data);
      packets.open--;
      packets.done.add(link);
      packets.failed = true;
      addGap(`Link ${link}: ${error}`);
    });
    onStream('world_error', (ev) => {
      if (packets?.source !== source) return;
      packets.failed = true;
      addGap(`${many ? 'Links' : 'Link'} ${list}: ${JSON.parse(ev.data).error}`);
      source.close();
    });
    onStream('error', (ev) => {
      if (packets?.source !== source) return;
      // After the run stopped, the connection will not come back.
      const reason = stopped();
      addGap(reason || JSON.parse(ev.data).error);
      trimRows();
      if (reason) source.close();
    });
    onStream('end', (ev) => {
      if (packets?.source !== source) return;
      source.close();
      if (JSON.parse(ev.data).reason === 'the world closed') addGap('The world closed.');
      else if (!packets.failed) addGap(many ? 'Every one of these links has closed.' : 'The link closed: both of its ends are gone.');
    });
    fitColumns();
    fit();
  }

  function queueEntry(entry) {
    entry.came = performance.now();
    // Only the last rows are ever shown, so only those are kept while the
    // view is paused or the tab is hidden. Gap notices share the same limit.
    const q = packets.paused ? packets.held : packets.queue;
    q.push(entry);
    if (q.length > MAX_ROWS * 2) q.splice(0, q.length - MAX_ROWS);
  }

  function closePackets() {
    invalidateSelection();
    streamCleanup.splice(0).forEach((remove) => remove());
    if (packets) packets.source.close();
    packets = null;
    drawer.hidden = true;
  }

  on($('close-drawer'), 'click', () => {
    closePackets();
    fit();
  });
  on($('pcap'), 'click', async () => {
    if (!packets) return;
    const current = packets;
    try {
      await download('pcap', current.list);
      if (packets === current) $('pcap-label').textContent = pcapLabel;
    } catch {
      if (packets === current) $('pcap-label').textContent = 'Download failed. Try again.';
    }
  });
  on($('pause'), 'click', () => {
    if (!packets) return;
    packets.paused = !packets.paused;
    $('pause').textContent = packets.paused ? `Resume` : 'Pause';
    if (!packets.paused) {
      packets.queue = packets.queue.concat(packets.held).slice(-MAX_ROWS);
      packets.held = [];
    }
  });
  on($('pfilter'), 'input', () => {
    for (const tr of prows.children) filterRow(tr);
  });

  // An address pair, `[a, b]`, matched in either direction: what an event
  // names as its local and peer ends. Null shows every row.
  let pair = null;
  function filterRow(tr) {
    const q = $('pfilter').value.trim().toLowerCase();
    const gap = tr.classList.contains('gap');
    const text = !q || (!gap && (tr.dataset.text || '').includes(q));
    const { src, dst } = tr.dataset;
    const ends = !pair || (!gap && ((src === pair[0] && dst === pair[1]) || (src === pair[1] && dst === pair[0])));
    tr.hidden = !(text && ends);
  }
  function setPair(next) {
    pair = next ? [String(next[0]), String(next[1])] : null;
    for (const tr of prows.children) filterRow(tr);
  }

  function addGap(text, parent = prows) {
    const tr = el('tr', { class: 'gap' }, parent);
    el('td', { colspan: hostColumn ? 9 : 8, text }, tr);
  }

  function showCounts() {
    const counts = [];
    if (packets.skipped) counts.push(`Sampled: ${fmtCount(packets.skipped)} packets not copied`);
    if (packets.evicted) counts.push(`Capture: ${fmtCount(packets.evicted)} copies evicted`);
    if (packets.missed) counts.push(`Subscriber: ${fmtCount(packets.missed)} rows missed`);
    $('sampled').hidden = !counts.length;
    $('sampled').textContent = counts.join(' · ');
    $('sampled').title = 'Sampling leaves packets uncopied. Capture eviction drops copies before decoding. Subscriber overruns lose decoded rows before delivery. Counts cover the loss reported by this history; expired rows may have carried more sampling or capture loss.';
  }

  function trimRows() {
    let extra = prows.children.length - MAX_ROWS;
    while (extra-- > 0) prows.firstChild.remove();
  }

  /// Adds the packets that came since the last frame, in one change to the
  /// table, and keeps the newest in view unless the viewer scrolled up.
  function flushPackets() {
    if (!packets || !packets.queue.length) return;
    const nearBottom = plist.scrollHeight - plist.scrollTop - plist.clientHeight < 40;
    let batch = packets.queue;
    packets.queue = [];
    if (packets.many) {
      // Merged links send their packets in turns, a little apart, and rows go
      // in time order. A packet goes in once every open link has sent one at
      // or after its time, since nothing earlier can follow; a link that has
      // sent nothing yet holds packets back for a moment. A tab opened late
      // so shows the history still kept at once.
      const now = performance.now();
      batch.sort((a, b) => a.t - b.t);
      const open = [...packets.flips.keys()].filter((link) => !packets.done.has(link));
      const reached = Math.min(...open.map((link) => packets.lastTime.get(link) ?? -Infinity));
      const ready = batch.findIndex((p) => p.t > reached && now - p.came < MERGE_HOLD_MS);
      if (ready !== -1) {
        // Everything later than the first packet still held waits with it.
        packets.queue = batch.slice(ready);
        batch = batch.slice(0, ready);
      }
      if (!batch.length) return;
    }
    if (!showConsole && consoleAddresses.length) {
      // Hidden console packets take no rows, so they cannot push the
      // world's own traffic out of the list.
      const before = packets.console;
      batch = batch.filter((p) => {
        if (p.gap || !fromConsole(p)) return true;
        packets.console++;
        if (p.skipped > 0) packets.skipped += p.skipped;
        return false;
      });
      if (packets.console !== before) { showCounts(); showConsoleNote(); }
      if (!batch.length) return;
    }
    const frag = document.createDocumentFragment();
    // A flood only ever shows its last rows.
    for (const p of batch.slice(-MAX_ROWS)) {
      if (p.gap) addGap(p.gap, frag);
      else addPacket(p, frag);
    }
    prows.appendChild(frag);
    fitColumns();
    trimRows();
    if (nearBottom) { plist.scrollTop = plist.scrollHeight; clearUnread(); }
    else if (jump) { unread += batch.length; jump.textContent = `↓ ${unread} new`; jump.hidden = false; }
  }

  function fitColumns() {
    if (!packets || !drawer.classList.contains('packet-panel')) return;
    for (const [field, width] of Object.entries(packets.widths)) {
      drawer.style.setProperty(`--packet-${field}`, `calc(${width}ch + 16px)`);
    }
  }

  function addPacket(p, parent) {
    if (p.skipped > 0) {
      packets.skipped += p.skipped;
      showCounts();
    }
    for (const field of ['src', 'dst', 'proto']) packets.widths[field] = Math.max(packets.widths[field], p[field].length);
    const time = p.t.toFixed(4);
    packets.widths.time = Math.max(packets.widths.time, time.length);
    packets.rows++;
    // One link numbers its own packets; merged links are numbered here.
    const no = packets.many ? packets.rows : p.seq;
    const tr = el('tr', { class: `${p.side === 1 ? 'back' : ''} ${p.skipped > 0 || p.evicted > 0 ? 'after-gap' : ''} ${p.tags.join(' ')}`, 'data-seq': p.seq, 'data-link': p.link }, parent);
    p.no = no;
    const cells = [no, time, '', p.src, p.dst, p.proto, p.len, p.info];
    cells.forEach((c, i) => {
      const td = el('td', i === 7 ? {} : i === 3 || i === 4 ? { title: String(c) } : { text: String(c) }, tr);
      // A narrow list hides the port; the cell's title keeps it.
      if (i === 3 || i === 4) {
        const [host, port] = endpoint(String(c));
        el('span', { class: 'addr', text: host }, td);
        if (port) el('span', { class: 'port', text: port }, td);
      }
      if (i === 2) {
        td.className = 'dir';
        el('i', {}, td);
      }
      if (i === 5) td.className = 'proto';
      td.classList.add(['c-no', 'c-time', 'c-dir', 'c-src', 'c-dst', 'c-proto', 'c-len', 'c-info'][i]);
      if (i === 2 && (hostColumn || packets.showHost)) el('td', { class: 'c-host mono', text: packets.showHost ? packets.hosts.get(p.link) || '—' : '' }, tr);
      if (i === 7) {
        const info = el('div', { class: 'packet-info' }, td);
        const text = el('span', { class: 'packet-info-text' }, info);
        el('span', { class: 'packet-info-protocol', text: `${p.proto} ` }, text);
        text.append(String(c));
        labelChips(info, labels.filter((label) => flowMatches(label.target, p)));
      }
    });
    tr.title = p.skipped > 0 ? `${p.info}\n(${p.skipped} packet${p.skipped === 1 ? '' : 's'} before this one not copied)` : p.info;
    if (p.evicted > 0) tr.title += `\n(${p.evicted} captured ${p.evicted === 1 ? 'copy' : 'copies'} before this one evicted before decoding)`;
    tr.dataset.text = `${p.src} ${p.dst} ${p.proto} ${p.info}`.toLowerCase();
    tr.dataset.src = p.src;
    tr.dataset.dst = p.dst;
    filterRow(tr);
    tr.classList.add('new-row');
    tr.addEventListener('click', () => showPacket(p, tr));
  }

  async function showPacket(p, tr) {
    if (!packets) return;
    invalidateSelection();
    const generation = selection;
    const history = packets;
    const request = new AbortController();
    detailRequest = request;
    const current = () => packets === history && selection === generation && !drawer.hidden;
    for (const r of prows.querySelectorAll('tr.on')) r.classList.remove('on');
    tr.classList.add('on');
    drawer.classList.add('has-packet');
    clearDetail('Loading packet…');
    try {
      const res = await packet(p, request.signal);
      if (!current()) return;
      if (!res.ok) {
        clearDetail('This packet is no longer kept. The dashboard keeps the last 4,096 packets of a link.');
        return;
      }
      const d = await res.json();
      if (!current()) return;
      d.side = p.side;
      renderDetail(d, p);
    } catch {
      if (current()) clearDetail('Could not load this packet. Select it again to retry.');
    } finally {
      if (detailRequest === request) detailRequest = null;
    }
  }

  function setLabels(value) {
    labels = value;
    for (const row of prows.querySelectorAll('tr')) {
      const info = row.querySelector('.packet-info');
      if (!info) continue;
      for (const chip of info.querySelectorAll('.label-chip')) chip.remove();
      labelChips(info, labels.filter((label) => flowMatches(label.target, { link: row.dataset.link, src: row.dataset.src, dst: row.dataset.dst })));
    }
  }

  function invalidateSelection() {
    drawer.classList.remove('has-packet');
    selection++;
    detailRequest?.abort();
    detailRequest = null;
  }

  let hexState = null;
  on($('tree'), 'pointerleave', () => {
    if (hexState) mark(...(hexState.pinned || [hexState.buf, null]));
  });

  function clearDetail(text) {
    $('tree').replaceChildren(el('p', { class: 'placeholder', text }));
    hexState = null;
    $('hex').hidden = true;
    $('hex-tabs').replaceChildren();
    $('hex-dump').replaceChildren();
  }

  function renderDetail(d, p) {
    const tree = $('tree');
    tree.replaceChildren();
    const host = packets.hosts.get(p.link);
    const head = el('div', { class: 'packet-detail-head' }, tree);
    const title = el('div', {}, head);
    el('b', { text: `Packet ${p.no}` }, title);
    el('span', { text: host ? ` · ${host}'s link, packet ${p.seq} · ${d.len} bytes at ${d.t.toFixed(6)} s` : `, ${d.len} bytes at ${d.t.toFixed(6)}s, ${d.side === 0 ? $('dir-a').textContent : $('dir-b').textContent}` }, title);
    onDetail(p, head);
    // The layers below the application start closed, as in Wireshark, unless
    // they are all there is.
    const low = /^(Internet Protocol|Transmission Control|User Datagram)/;
    const onlyLow = d.layers.every((l) => low.test(l.name));
    for (const layer of d.layers) {
      const det = el('details', onlyLow || !low.test(layer.name) ? { open: '' } : {}, tree);
      const s = el('summary', {}, det);
      el('b', { text: layer.name }, s);
      if (layer.summary) el('span', { text: `, ${layer.summary}` }, s);
      s.addEventListener('pointerenter', () => mark(layer.buf, layer.range));
      for (const f of layer.fields) {
        const row = el('div', { class: 'field' }, det);
        el('span', { class: 'k', text: f.name }, row);
        el('span', { class: 'v', text: f.value }, row);
        if (f.range) {
          row.addEventListener('pointerenter', () => mark(layer.buf, f.range));
          row.addEventListener('click', () => {
            for (const r of tree.querySelectorAll('.field.on')) r.classList.remove('on');
            row.classList.add('on');
            hexState.pinned = [layer.buf, f.range];
            mark(layer.buf, f.range);
          });
        }
      }
    }

    hexState = { buffers: d.buffers.map((b) => hexBytes(b.hex)), names: d.buffers.map((b) => b.name), buf: 0, range: null, pinned: null };
    const tabs = $('hex-tabs');
    tabs.replaceChildren();
    if (hexState.buffers.length > 1) {
      hexState.names.forEach((name, i) => {
        const b = el('button', { type: 'button', text: `${name} (${hexState.buffers[i].length})` }, tabs);
        b.addEventListener('click', () => mark(i, null));
      });
    }
    $('hex').hidden = false;
    // Open the bytes of the highest layer, such as decrypted HTTP/2.
    const top = d.layers[d.layers.length - 1];
    hexState.pinned = top ? [top.buf, top.range] : null;
    mark(top ? top.buf : 0, top ? top.range : null);
  }

  function hexBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function mark(buf, range) {
    if (!hexState) return;
    hexState.buf = buf;
    hexState.range = range;
    [...$('hex-tabs').children].forEach((b, i) => b.classList.toggle('on', i === buf));
    const bytes = hexState.buffers[buf] || new Uint8Array();
    const [ra, rb] = range || [-1, -1];
    const pre = $('hex-dump');
    pre.replaceChildren();
    const limit = Math.min(bytes.length, 8192);
    let firstMarked = null;
    for (let off = 0; off < limit; off += 16) {
      const line = document.createDocumentFragment();
      line.append(el('span', { class: 'off', text: off.toString(16).padStart(4, '0') + '  ' }));
      let hexPart = '';
      let asciiPart = '';
      const flush = (marked) => {
        if (!hexPart && !asciiPart) return;
        if (marked) {
          const m = el('mark', { text: hexPart });
          line.append(m);
          if (!firstMarked) firstMarked = m;
        } else line.append(hexPart);
        hexPart = '';
      };
      let inMark = false;
      for (let i = off; i < off + 16; i++) {
        const isMarked = i >= ra && i < rb;
        if (isMarked !== inMark) {
          flush(inMark);
          inMark = isMarked;
        }
        hexPart += i < limit ? bytes[i].toString(16).padStart(2, '0') : '  ';
        hexPart += i === off + 7 ? '  ' : ' ';
      }
      flush(inMark);
      inMark = false;
      line.append(' ');
      let ascii = '';
      for (let i = off; i < Math.min(off + 16, limit); i++) {
        const isMarked = i >= ra && i < rb;
        if (isMarked !== inMark) {
          if (inMark) line.append(el('mark', { text: ascii }));
          else line.append(ascii);
          ascii = '';
          inMark = isMarked;
        }
        const c = bytes[i];
        ascii += c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
      }
      if (inMark) line.append(el('mark', { text: ascii }));
      else line.append(ascii);
      void asciiPart;
      line.append('\n');
      pre.append(line);
    }
    if (bytes.length > limit) pre.append(el('span', { class: 'off', text: `… ${bytes.length - limit} more bytes` }));
    if (firstMarked) firstMarked.scrollIntoView({ block: 'nearest' });
  }

  // Resizing the drawer by its top edge.
  on($('grip'), 'pointerdown', (ev) => {
    stopDrag();
    const startY = ev.clientY;
    const startH = drawer.getBoundingClientRect().height;
    const grip = ev.target;
    grip.setPointerCapture(ev.pointerId);
    const move = (m) => {
      const h = Math.max(160, Math.min(innerHeight - 160, startH - (m.clientY - startY)));
      drawer.style.setProperty('--drawer', `${h}px`);
    };
    const up = stopDrag = () => {
      grip.removeEventListener('pointermove', move);
      grip.removeEventListener('pointerup', up);
    };
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', up);
  });

  return { dispose() {
    closePackets();
    stopDrag();
    cleanup.splice(0).forEach((remove) => remove());
    prows.replaceChildren();
    clearDetail('Select a packet to see its layers.');
  }, open: openPackets, openLinks, close: closePackets, flush: flushPackets, setPair, setLabels,
  /// Packets received but not shown yet, or -1 while no stream is open.
  queued: () => (packets ? packets.queue.length + packets.held.length : -1) };
}
