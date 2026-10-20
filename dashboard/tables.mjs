// The map's tables: tooltip contents, the empty notice, the breadcrumb, and
// the side panel's sections, lists and event rows. components/map.mjs passes
// in the state and view, formatting, the graph's rates and helpers, and the
// selection, focus and packet steps the rows link to, and calls `refresh`
// once a frame.
import { fmtRunTime } from './format.mjs';

export function createTables({ $, el, state, view, runTime, fmtDuration, fmtBytes, fmtCount, fmtRate, plural, where, nodeLabel, tone, drawnSource, liveRate, dRate, dCounts, dBytesRate, ends, dEdgesOf, groupChain, parentOf, isOpen, select, toggleGroup, applySearch, focusNode, focusGroup, openPackets, openLinks }) {
  // ---------------------------------------------------------------------------
  // Tooltip contents

  function table(rows) {
    const t = el('table');
    for (const [k, v] of rows) {
      const tr = el('tr', {}, t);
      el('td', { text: k }, tr);
      el('td', { text: v }, tr);
    }
    return t;
  }

  /// Packets a second on the drawn edges of an item.
  function itemRate(n) {
    let pps = 0;
    for (const id of dEdgesOf(n)) {
      const d = view.dedges.get(id);
      if (d) {
        const r = dRate(d);
        pps += r[0] + r[1];
      }
    }
    return pps;
  }

  function nodeTip(n) {
    const out = [el('h3', { text: n.name })];
    if (n.kind === 'sandbox') {
      out.push(el('div', { class: 'sub', text: 'sandbox, attached to the world' }));
    } else {
      out.push(el('div', { class: 'sub', text: `${n.file}:${n.line}` }));
    }
    const rows = [];
    rows.push(['Links', String(n.edges.size)]);
    rows.push(['Packets/s on its links', fmtRate(itemRate(n))]);
    if (n.started !== undefined) rows.push(['Running for', fmtDuration(runTime() - n.started)]);
    if (n.drops) rows.push(['Packets dropped', fmtCount(n.drops)]);
    if (n.group && state.groups.has(n.group)) rows.push(['Group', groupChain(n.group).map((g) => g.name).join(' › ')]);
    out.push(table(rows));
    if (!n.pinned) out.push(el('div', { class: 'hint', text: 'Drag to move it' }));
    return out;
  }

  function groupTip(gid) {
    const g = state.groups.get(gid);
    const info = view.info.get(gid);
    if (!g || !info) return [];
    const out = [el('h3', { text: g.name })];
    out.push(el('div', { class: 'sub', text: groupChain(gid).map((c) => c.name).join(' › ') }));
    const item = view.items.get(gid);
    const rows = [['Tasks', String(info.tasks)]];
    if (info.sandboxes) rows.push(['Sandboxes', String(info.sandboxes)]);
    rows.push(['Packets/s in and out', fmtRate(groupRate(gid))]);
    out.push(table(rows));
    out.push(el('div', { class: 'hint', text: item ? 'Double-click to open it, drag to move it' : 'Double-click the name to close it' }));
    return out;
  }

  /// Packets a second on the drawn edges that cross group `gid`'s edge.
  function groupRate(gid) {
    let pps = 0;
    for (const d of crossingEdges(gid)) {
      const r = dRate(d);
      pps += r[0] + r[1];
    }
    return pps;
  }

  /// The drawn edges with one end inside group `gid` and one outside.
  function crossingEdges(gid) {
    const inside = (did) => {
      if (did === gid) return true;
      let c = view.contOf.get(did);
      while (c != null) {
        if (c === gid) return true;
        c = parentOf(c);
      }
      return false;
    };
    return [...view.dedges.values()].filter((d) => inside(d.a) !== inside(d.b));
  }

  function edgeTip(d) {
    const [a, b, swapped] = ends(d);
    const rate = dRate(d);
    const raw = dCounts(d);
    const c = swapped ? [raw[2], raw[3], raw[0], raw[1]] : raw;
    const out = [el('h3', { text: `${nodeLabel(a)} ↔ ${nodeLabel(b)}` })];
    if (d.members.length > 1) out.push(el('div', { class: 'sub', text: `${d.members.length} links, added up${d.label ? `, route ${d.label}` : ''}` }));
    else if (d.label) out.push(el('div', { class: 'sub', text: `route ${d.label}` }));
    else out.push(el('div', { class: 'sub', text: d.id }));
    out.push(
      table([
        [`${nodeLabel(a)} → ${nodeLabel(b)}`, `${fmtCount(c[0])} pkts, ${fmtBytes(c[1])}`],
        [`${nodeLabel(b)} → ${nodeLabel(a)}`, `${fmtCount(c[2])} pkts, ${fmtBytes(c[3])}`],
        ['Now', `${fmtRate(rate[0] + rate[1])} pkts/s, ${fmtBytes(Math.round(dBytesRate(d)))}/s`],
      ]),
    );
    out.push(el('div', { class: 'hint', text: 'Click to watch its packets' }));
    return out;
  }

  // ---------------------------------------------------------------------------
  // The empty notice, the breadcrumb and the side panel

  function renderEmpty() {
    const empty = !state.nodes.size;
    $('empty').hidden = !empty;
    if (empty && state.connected) {
      $('empty-title').textContent = state.ended ? 'The world has stopped' : 'Waiting for the world';
    }
    if (state.search) applySearch();
  }

  /// The groups around the selection, as a path the viewer can climb.
  function renderCrumbs() {
    const nav = $('crumbs');
    const sel = state.selected;
    let gid = null;
    if (sel?.kind === 'group') gid = sel.id;
    else if (sel?.kind === 'node') gid = state.nodes.get(sel.id)?.group || null;
    const chain = groupChain(gid);
    if (!chain.length) {
      nav.hidden = true;
      return;
    }
    const parts = [];
    const world = el('button', { type: 'button', text: 'World' });
    world.addEventListener('click', () => select(null));
    parts.push(world);
    chain.forEach((g, i) => {
      parts.push(el('span', { class: 'sep', 'aria-hidden': 'true', text: '›' }));
      const last = i === chain.length - 1 && sel.kind === 'group';
      const b = el('button', { type: 'button', text: g.name, class: last ? 'here' : '' });
      if (last) b.setAttribute('aria-current', 'true');
      b.addEventListener('click', () => focusGroup(g.id));
      parts.push(b);
    });
    if (sel.kind === 'node') {
      const n = state.nodes.get(sel.id);
      parts.push(el('span', { class: 'sep', 'aria-hidden': 'true', text: '›' }));
      parts.push(el('span', { class: 'leaf', text: n.name }));
    }
    nav.replaceChildren(...parts);
    nav.hidden = false;
  }

  function section(title, count) {
    const s = el('section');
    const h = el('h2', { text: title }, s);
    if (count !== undefined) el('small', { text: count }, h);
    return s;
  }

  function kv(parent, rows) {
    const dl = el('dl', { class: 'kv' }, parent);
    for (const [k, v, mono] of rows) {
      el('dt', { text: k }, dl);
      el('dd', { text: v, class: mono ? 'mono' : '' }, dl);
    }
    return dl;
  }

  function linkButton(text, onClick) {
    const b = el('button', { class: 'link what', type: 'button', text });
    b.addEventListener('click', onClick);
    return b;
  }

  function eventsList(parent, events) {
    renderEvents(parent, events, { el, state, drawnSource, tone, focusNode, select });
  }

  /// What group `gid` holds directly: groups, then tasks and sandboxes by
  /// where they were started.
  function groupMembers(gid) {
    const groups = [...state.groups.values()].filter((g) => parentOf(g.id) === gid && view.info.get(g.id)?.tasks + view.info.get(g.id)?.sandboxes > 0);
    const leaves = [...state.nodes.values()].filter((n) => (n.group && state.groups.has(n.group) ? n.group : null) === gid);
    return { groups, leaves };
  }

  function membersList(parent, gid) {
    const { groups, leaves } = groupMembers(gid);
    const ul = el('ul', { class: 'rows' }, parent);
    for (const g of groups.sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const li = el('li', {}, ul);
      li.append(linkButton(g.name, () => focusGroup(g.id)));
      el('span', { class: 'where', text: isOpen(g.id) ? 'open' : 'group' }, li);
      el('span', { class: 'count', text: `${fmtRate(groupRate(g.id))}/s` }, li);
    }
    const bySite = new Map();
    for (const n of leaves) {
      const key = n.kind === 'sandbox' ? `s|${n.id}` : `${n.name}|${n.file}:${n.line}`;
      const e = bySite.get(key) || { n, count: 0 };
      e.count++;
      bySite.set(key, e);
    }
    for (const { n, count } of [...bySite.values()].sort((x, y) => (x.n.name < y.n.name ? -1 : 1))) {
      const li = el('li', {}, ul);
      li.append(linkButton(n.name, () => focusNode(n.id)));
      el('span', { class: 'where', text: n.kind === 'sandbox' ? 'sandbox' : where(n) }, li);
      el('span', { class: 'count', text: count > 1 ? `×${count}` : '' }, li);
    }
    if (!ul.children.length) el('li', { class: 'quiet', text: 'Nothing running.' }, ul);
  }

  function renderSide() {
    const side = $('side');
    const out = [];
    const sel = state.selected;
    const now = runTime();
    if (sel && sel.kind === 'node' && state.nodes.get(sel.id)) {
      const n = state.nodes.get(sel.id);
      const s = el('section');
      el('h3', { class: 'selection-title', text: n.name }, s);
      el('p', { class: 'selection-kind', text: n.kind === 'sandbox' ? 'A sandbox attached to the world' : n.kind === 'world' ? 'The world function' : 'A task' }, s);
      const rows = [];
      if (n.file) rows.push(['Spawned at', `${n.file}:${n.line}`, true]);
      if (n.started !== undefined) rows.push(['Running for', fmtDuration(now - n.started)]);
      if (n.drops) rows.push(['Dropped', `${fmtCount(n.drops)} packets`]);
      kv(s, rows);
      if (n.group && state.groups.has(n.group)) {
        const row = el('p', { class: 'lead' }, s);
        row.append('In the group ');
        row.append(linkButton(state.groups.get(n.group).name, () => focusGroup(n.group)));
      }
      if (n.parent && state.nodes.get(n.parent)) {
        const p = state.nodes.get(n.parent);
        const row = el('p', { class: 'lead' }, s);
        row.append('Started by ');
        row.append(linkButton(p.name, () => focusNode(p.id)));
      }
      out.push(s);
      const links = section('Links', n.edges.size);
      const ul = el('ul', { class: 'rows' }, links);
      for (const id of n.edges) {
        const e = state.edges.get(id);
        if (!e) continue;
        const other = state.nodes.get(e.a === n.id ? e.b : e.a);
        const li = el('li', {}, ul);
        li.append(
          linkButton(`${nodeLabel(other)}${e.label ? `  ${e.label}` : ''}`, () => {
            openLinks(nodeLabel(n), nodeLabel(other), [{ e, flip: e.a !== n.id }], e.label);
          }),
        );
        const r = liveRate(e);
        el('span', { class: 'count', text: `${fmtRate(r[0] + r[1])}/s` }, li);
      }
      out.push(links);
      const ev = section('Events');
      eventsList(ev, state.events.filter((x) => x.node === n.id));
      out.push(ev);
    } else if (sel && sel.kind === 'group' && state.groups.has(sel.id)) {
      const g = state.groups.get(sel.id);
      const info = view.info.get(sel.id);
      const s = el('section');
      el('h3', { class: 'selection-title', text: g.name }, s);
      el('p', { class: 'selection-kind', text: `A group, ${isOpen(sel.id) ? 'open' : 'closed'}` }, s);
      const rows = [['Tasks', String(info?.tasks || 0)]];
      if (info?.sandboxes) rows.push(['Sandboxes', String(info.sandboxes)]);
      rows.push(['In and out now', `${fmtRate(groupRate(sel.id))} packets/s`]);
      kv(s, rows);
      const tools = el('div', { class: 'tools' }, s);
      const b = el('button', { class: 'button', type: 'button', text: isOpen(sel.id) ? 'Close the group' : 'Open the group' }, tools);
      b.addEventListener('click', () => toggleGroup(sel.id));
      out.push(s);
      const crossing = crossingEdges(sel.id);
      const links = section('In and out', crossing.length);
      if (!crossing.length) el('p', { class: 'quiet', text: 'No links cross this group’s edge.' }, links);
      const ul = el('ul', { class: 'rows' }, links);
      for (const d of crossing) {
        const [a, b2] = ends(d);
        const li = el('li', {}, ul);
        li.append(
          linkButton(`${nodeLabel(a)} ↔ ${nodeLabel(b2)}${d.members.length > 1 ? ` (${d.members.length} links)` : ''}`, () => {
            select({ kind: 'edge', id: d.id });
            openPackets(d.id);
          }),
        );
        const r = dRate(d);
        el('span', { class: 'count', text: `${fmtRate(r[0] + r[1])}/s` }, li);
      }
      out.push(links);
      const m = section('Inside');
      membersList(m, sel.id);
      out.push(m);
    } else if (sel && sel.kind === 'ended') {
      // A task that has ended, known only from the events it sent.
      const n = sel.event;
      const s = el('section');
      el('h3', { class: 'selection-title', text: n.task || 'A task' }, s);
      el('p', { class: 'selection-kind', text: 'A task that has ended' }, s);
      if (n.file) kv(s, [['Spawned at', `${n.file}:${n.line}`, true]]);
      const parent = n.parent && state.nodes.get(n.parent);
      if (parent) {
        const row = el('p', { class: 'lead' }, s);
        row.append('Started by ');
        row.append(linkButton(parent.name, () => focusNode(parent.id)));
      }
      out.push(s);
      const ev = section('Events');
      eventsList(ev, state.events.filter((x) => x.node === sel.id));
      out.push(ev);
    } else if (sel && sel.kind === 'edge' && view.dedges.get(sel.id)) {
      const d = view.dedges.get(sel.id);
      const [a, b, swapped] = ends(d);
      const raw = dCounts(d);
      const c = swapped ? [raw[2], raw[3], raw[0], raw[1]] : raw;
      const s = el('section');
      el('h3', { class: 'selection-title', text: `${nodeLabel(a)} ↔ ${nodeLabel(b)}` }, s);
      const kind = d.members.length > 1 ? `${d.members.length} links, added up` : d.label ? `A link, routed for ${d.label}` : 'A link between two tasks';
      el('p', { class: 'selection-kind', text: kind }, s);
      const r = dRate(d);
      kv(s, [
        [`${nodeLabel(a)} sent`, `${fmtCount(c[0])} packets, ${fmtBytes(c[1])}`],
        [`${nodeLabel(b)} sent`, `${fmtCount(c[2])} packets, ${fmtBytes(c[3])}`],
        ['Now', `${fmtRate(r[0] + r[1])} packets/s`],
      ]);
      out.push(s);
      if (d.members.length > 1) {
        const ls = section('Links', d.members.length);
        const ul = el('ul', { class: 'rows' }, ls);
        for (const { e } of d.members) {
          const ea = state.nodes.get(e.a);
          const eb = state.nodes.get(e.b);
          const li = el('li', {}, ul);
          li.append(linkButton(`${nodeLabel(ea)} ↔ ${nodeLabel(eb)}${e.label ? `  ${e.label}` : ''}`, () => openLinks(nodeLabel(ea), nodeLabel(eb), [{ e, flip: false }], e.label)));
          const lr = liveRate(e);
          el('span', { class: 'count', text: `${fmtRate(lr[0] + lr[1])}/s` }, li);
        }
        out.push(ls);
      }
    } else {
      const all = [...state.nodes.values()];
      const s = section('This world');
      if (!state.connected) el('p', { class: 'quiet', text: 'Connecting to the world.' }, s);
      else if (!all.length && !state.startedMs) el('p', { class: 'quiet', text: 'No world is running yet.' }, s);
      else {
        let packets = 0;
        let bytes = 0;
        for (const e of state.edges.values()) {
          if (state.nodes.get(e.b)?.kind === 'sandbox') {
            packets += e.c[0] + e.c[2];
            bytes += e.c[1] + e.c[3];
          }
        }
        kv(s, [
          [state.ended ? 'Ran for' : 'Running for', fmtDuration(now)],
          ['Started', state.startedMs ? new Date(state.startedMs).toLocaleTimeString() : ''],
          ['Sandbox traffic', `${fmtCount(packets)} packets, ${fmtBytes(bytes)}`],
        ]);
      }
      out.push(s);
      const boxes = all.filter((n) => n.kind === 'sandbox');
      const sb = section('Sandboxes', boxes.length);
      if (!boxes.length) el('p', { class: 'quiet', text: 'None attached. Each fictionet attach adds one.' }, sb);
      else {
        const ul = el('ul', { class: 'rows' }, sb);
        for (const n of boxes.sort((x, y) => (x.name < y.name ? -1 : 1))) {
          const li = el('li', {}, ul);
          li.append(linkButton(n.name, () => focusNode(n.id)));
          let r = 0;
          for (const id of n.edges) {
            const e = state.edges.get(id);
            if (e) r += liveRate(e)[0] + liveRate(e)[1];
          }
          el('span', { class: 'count', text: `${fmtRate(r)}/s` }, li);
        }
      }
      out.push(sb);
      // Groups, as a tree.
      const tops = [...state.groups.values()].filter((g) => !parentOf(g.id));
      if (tops.length) {
        const gs = section('Groups', state.groups.size);
        const ul = el('ul', { class: 'rows tree' }, gs);
        const walk = (g, depth) => {
          const li = el('li', {}, ul);
          li.style.paddingLeft = `${depth * 14}px`;
          li.append(linkButton(g.name, () => focusGroup(g.id)));
          el('span', { class: 'where', text: plural(view.info.get(g.id)?.tasks || 0, 'task') }, li);
          el('span', { class: 'count', text: `${fmtRate(groupRate(g.id))}/s` }, li);
          for (const c of [...state.groups.values()].filter((x) => parentOf(x.id) === g.id).sort((a, b) => (a.name < b.name ? -1 : 1))) walk(c, depth + 1);
        };
        for (const g of tops.sort((a, b) => (a.name < b.name ? -1 : 1))) walk(g, 0);
        out.push(gs);
      }
      // Tasks, grouped by where they were spawned. Tasks with no links,
      // such as one per connection, are only listed here.
      const sites = new Map();
      for (const n of all) {
        if (n.kind === 'sandbox') continue;
        const key = `${n.name}|${n.file}:${n.line}`;
        const g = sites.get(key) || { n, count: 0, linked: 0 };
        g.count++;
        if (n.edges.size) g.linked++;
        sites.set(key, g);
      }
      const ts = section('Tasks', all.length - boxes.length);
      const ul = el('ul', { class: 'rows' }, ts);
      const q = state.search;
      for (const g of [...sites.values()].sort((x, y) => y.count - x.count || (x.n.name < y.n.name ? -1 : 1))) {
        if (q && !`${g.n.name} ${g.n.file}:${g.n.line}`.toLowerCase().includes(q)) continue;
        const li = el('li', {}, ul);
        const target = all.find((m) => m.name === g.n.name && m.file === g.n.file && m.line === g.n.line && m.edges.size) || g.n;
        li.append(linkButton(g.n.name, () => focusNode(target.id)));
        el('span', { class: 'where', text: where(g.n) }, li);
        el('span', { class: 'count', text: g.count > 1 ? `×${g.count}` : '' }, li);
      }
      out.push(ts);
      const ev = section('Events', state.events.length || undefined);
      eventsList(ev, state.events);
      out.push(ev);
    }
    side.replaceChildren(...out);
  }

  let lastSide = 0;
  let lastEmpty = 0;

  /// Refreshes the empty notice and search, and the side panel and
  /// breadcrumb when they are due.
  function refresh(now) {
    if (now - lastEmpty > 500 || state.sideDirty) {
      lastEmpty = now;
      renderEmpty();
    }
    // The side panel is rebuilt when something changed, and once a second
    // for its rates, unless the viewer is pointing at it or typing in it.
    const side = $('side');
    const busy = side.matches(':hover') || side.contains(side.ownerDocument.activeElement);
    if (state.sideDirty || (now - lastSide > 1000 && !busy)) {
      lastSide = now;
      renderSide();
      renderCrumbs();
      state.sideDirty = false;
    }
  }

  return { nodeTip, groupTip, edgeTip, renderSide, refresh };
}

// The map's side panel list of recent events.
export function renderEvents(parent, events, { el, state, drawnSource, tone, focusNode, select }) {
  if (!events.length) {
    el('p', { class: 'quiet', text: 'No events yet. They appear here as the world runs.' }, parent);
    return;
  }
  const ul = el('ul', { class: 'rows' }, parent);
  for (const n of events.slice(-60).reverse()) {
    const li = el('li', { class: 'event-row' }, ul);
    el('time', { text: fmtRunTime(n.at) }, li);
    const node = state.nodes.get(n.node) || drawnSource(n);
    const head = el('span', {}, li);
    el('span', { class: `kind ${tone(n)}`, text: `${n.source}.${n.kind}` }, head);
    if (n.task || node) {
      head.append(' from ');
      const b = el('button', { class: 'link', type: 'button', text: n.task || node.name }, head);
      b.title = n.file ? `${n.file}:${n.line}` : '';
      b.addEventListener('click', () => {
        if (state.nodes.get(n.node)) focusNode(n.node);
        else select({ kind: 'ended', id: n.node, event: n });
      });
    }
    el('span', { class: 'text', text: n.summary || eventText(n.fields) }, li);
  }
}

/// An event's fields as `key value` pairs, or as JSON when they are not
/// an object.
export function eventText(data) {
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    return Object.entries(data)
      .map(([k, v]) => `${k} ${typeof v === 'object' ? JSON.stringify(v) : v}`)
      .join(', ');
  }
  return JSON.stringify(data);
}
