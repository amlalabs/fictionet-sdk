// The packet drawer: its stream, queue, selection, detail and hex view.
// The caller passes DOM helpers, graph links, labels and orientation, and a fit callback.
export function createPackets({ $, el, packetStream, packet, getEdge, ends, nodeLabel, fmtCount, fit }) {
  // ---------------------------------------------------------------------------
  // The packet drawer

  const drawer = $('drawer');
  const prows = $('prows');
  const plist = $('plist');
  // What the drawer watches: { links: [{ id, flip }], source, paused, held,
  // queue, skipped, rows }. A packet's side is turned to the drawn edge's:
  // 0 from its first end, 1 from its second.
  let packets = null;
  /// Rows the packet list keeps.
  const MAX_ROWS = 3000;
  /// How long a merged packet view holds packets to put them in order.
  const MERGE_HOLD_MS = 400;

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
    drawer.hidden = false;
    const many = members.length > 1;
    const count = total > members.length ? `  (the busiest ${members.length} of ${total} links)` : many ? `  (${members.length} links)` : '';
    $('drawer-title').textContent = `${fromName} ↔ ${toName}${label ? `  ${label}` : ''}${count}`;
    $('dir-a').textContent = `${fromName} → ${toName}`;
    $('dir-b').textContent = `${toName} → ${fromName}`;
    const list = members.map((m) => m.e.id).join(',');
    $('pcap').href = `api/pcap?link=${list}`;
    $('pcap').setAttribute('download', many ? 'fictionet-links.pcapng' : `fictionet-${list}.pcapng`);
    $('pause').textContent = 'Pause';
    $('sampled').hidden = true;
    prows.replaceChildren();
    $('tree').replaceChildren(el('p', { class: 'placeholder', text: many ? 'Packets from all of these links appear here, merged, as they cross. Select one to see its layers.' : 'Packets appear here as they cross the link. Select one to see its layers.' }));
    $('hex').hidden = true;
    const flips = new Map(members.map((m) => [m.e.id, m.flip]));
    const source = packetStream(list, () => {
      if (packets?.source !== source) return;
      // A new subscription replays retained history, possibly with restarted
      // sequence numbers. Replace its state before accepting any replay.
      packets = { ...packets, rows: 0, held: [], queue: [], skipped: 0, open: members.length };
      prows.replaceChildren();
      addGap('Packet history reloaded after reconnect.');
      $('sampled').hidden = true;
      $('sampled').textContent = '';
      $('tree').replaceChildren(el('p', { class: 'placeholder', text: 'Packet history reloaded after reconnect. Select a packet to see its layers.' }));
      hexState = null;
      $('hex').hidden = true;
      $('hex-tabs').replaceChildren();
      $('hex-dump').replaceChildren();
    });
    packets = { flips, many, source, rows: 0, paused: false, held: [], queue: [], skipped: 0, open: members.length };
    source.addEventListener('packet', (ev) => {
      const p = JSON.parse(ev.data);
      if (!packets || packets.source !== source) return;
      p.link = p.link || list;
      p.came = performance.now();
      if (flips.get(p.link)) p.side = 1 - p.side;
      // Only the last rows are ever shown, so only those are kept while the
      // view is paused or the tab is hidden.
      const q = packets.paused ? packets.held : packets.queue;
      q.push(p);
      if (q.length > MAX_ROWS * 2) q.splice(0, q.length - MAX_ROWS);
    });
    source.addEventListener('link_end', () => {
      if (packets?.source === source) packets.open--;
    });
    source.addEventListener('end', () => {
      source.close();
      addGap(many ? 'Every one of these links has closed.' : 'The link closed: both of its ends are gone.');
    });
    fit();
  }

  function closePackets() {
    if (packets) packets.source.close();
    packets = null;
    drawer.hidden = true;
  }

  $('close-drawer').addEventListener('click', () => {
    closePackets();
    fit();
  });
  $('pause').addEventListener('click', () => {
    if (!packets) return;
    packets.paused = !packets.paused;
    $('pause').textContent = packets.paused ? `Resume` : 'Pause';
    if (!packets.paused) {
      packets.queue = packets.queue.concat(packets.held).slice(-MAX_ROWS);
      packets.held = [];
    }
  });
  $('pfilter').addEventListener('input', () => {
    for (const tr of prows.children) filterRow(tr);
  });

  function filterRow(tr) {
    const q = $('pfilter').value.trim().toLowerCase();
    tr.hidden = !!q && (tr.classList.contains('gap') || !(tr.dataset.text || '').includes(q));
  }

  function addGap(text, parent = prows) {
    const tr = el('tr', { class: 'gap' }, parent);
    el('td', { colspan: 8, text }, tr);
  }

  /// Adds the packets that came since the last frame, in one change to the
  /// table, and keeps the newest in view unless the viewer scrolled up.
  function flushPackets() {
    if (!packets || !packets.queue.length) return;
    const nearBottom = plist.scrollHeight - plist.scrollTop - plist.clientHeight < 40;
    let batch = packets.queue;
    packets.queue = [];
    if (packets.many) {
      // Merged links send their packets in turns, a little apart: hold each
      // packet for a moment, and add them in time order.
      const now = performance.now();
      batch.sort((a, b) => a.t - b.t);
      const ready = batch.findIndex((p) => now - p.came < MERGE_HOLD_MS);
      if (ready !== -1) {
        // Everything later than the first packet still held waits with it.
        packets.queue = batch.slice(ready);
        batch = batch.slice(0, ready);
      }
      if (!batch.length) return;
    }
    const frag = document.createDocumentFragment();
    // A flood only ever shows its last rows.
    for (const p of batch.slice(-MAX_ROWS)) addPacket(p, frag);
    prows.appendChild(frag);
    let extra = prows.children.length - MAX_ROWS;
    while (extra-- > 0) prows.firstChild.remove();
    if (nearBottom) plist.scrollTop = plist.scrollHeight;
  }

  function addPacket(p, parent) {
    if (p.skipped > 0) {
      packets.skipped += p.skipped;
      $('sampled').hidden = false;
      $('sampled').textContent = `Sampled: ${fmtCount(packets.skipped)} packets not copied`;
      $('sampled').title = 'The link is busy, so the dashboard copies some of its packets, not all. The rows with a dashed line above them follow packets that were not copied.';
    }
    packets.rows++;
    // One link numbers its own packets; merged links are numbered here.
    const no = packets.many ? packets.rows : p.seq;
    const tr = el('tr', { class: `${p.side === 1 ? 'back' : ''} ${p.skipped > 0 ? 'after-gap' : ''} ${p.tags.join(' ')}`, 'data-seq': p.seq, 'data-link': p.link }, parent);
    const cells = [no, p.t.toFixed(4), '', p.src, p.dst, p.proto, p.len, p.info];
    cells.forEach((c, i) => {
      const td = el('td', { text: String(c) }, tr);
      if (i === 2) {
        td.className = 'dir';
        el('i', {}, td);
      }
      if (i === 5) td.className = 'proto';
    });
    tr.title = p.skipped > 0 ? `${p.info}\n(${p.skipped} packet${p.skipped === 1 ? '' : 's'} before this one not copied)` : p.info;
    tr.dataset.text = `${p.src} ${p.dst} ${p.proto} ${p.info}`.toLowerCase();
    filterRow(tr);
    tr.addEventListener('click', () => showPacket(p, tr));
  }

  async function showPacket(p, tr) {
    if (!packets) return;
    const history = packets;
    for (const r of prows.querySelectorAll('tr.on')) r.classList.remove('on');
    tr.classList.add('on');
    const res = await packet(p);
    if (packets !== history) return;
    if (!res.ok) {
      $('tree').replaceChildren(el('p', { class: 'placeholder', text: 'This packet is no longer kept. The dashboard keeps the last 4,096 packets of a link.' }));
      return;
    }
    const d = await res.json();
    if (packets !== history) return;
    d.side = p.side;
    renderDetail(d);
  }

  let hexState = null;

  function renderDetail(d) {
    const tree = $('tree');
    tree.replaceChildren();
    const head = el('details', { open: '' }, tree);
    const sum = el('summary', {}, head);
    el('b', { text: `Packet ${d.seq}` }, sum);
    el('span', { text: `, ${d.len} bytes at ${d.t.toFixed(6)}s, ${d.side === 0 ? $('dir-a').textContent : $('dir-b').textContent}` }, sum);
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
    tree.addEventListener('pointerleave', () => {
      if (hexState) mark(...(hexState.pinned || [hexState.buf, null]));
    });
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
  $('grip').addEventListener('pointerdown', (ev) => {
    const startY = ev.clientY;
    const startH = drawer.getBoundingClientRect().height;
    const grip = ev.target;
    grip.setPointerCapture(ev.pointerId);
    const move = (m) => {
      const h = Math.max(160, Math.min(innerHeight - 160, startH - (m.clientY - startY)));
      drawer.style.setProperty('--drawer', `${h}px`);
    };
    const up = () => {
      grip.removeEventListener('pointermove', move);
      grip.removeEventListener('pointerup', up);
    };
    grip.addEventListener('pointermove', move);
    grip.addEventListener('pointerup', up);
  });

  return { open: openPackets, openLinks, close: closePackets, flush: flushPackets };
}
