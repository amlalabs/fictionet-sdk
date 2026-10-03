// Groups in the Fictionet dashboard: which tasks a closed group stands for,
// and which drawn edges stand for which links. Plain functions over the
// graph as the observe API sends it, with no drawing, so they can be
// tested on their own (groups.test.js). app.js draws what they work out.
'use strict';

const FictionetGroups = (() => {
  /// The groups `gid` is in, outermost first, ending with `gid` itself.
  /// `groups` maps a group id to { id, name, parent }.
  function chain(groups, gid) {
    const out = [];
    let g = gid ? groups.get(gid) : null;
    for (let hops = 0; g && hops < 64; hops++) {
      out.unshift(g);
      g = g.parent ? groups.get(g.parent) : null;
    }
    return out;
  }

  /// The group `gid` is inside, if the dashboard knows it.
  function parentOf(groups, gid) {
    const p = groups.get(gid)?.parent;
    return p && groups.has(p) ? p : null;
  }

  /// A task or sandbox that is drawn: a sandbox, or a task with links.
  /// `edges` is the set of its links.
  const shown = (n) => n.kind === 'sandbox' || n.edges.size > 0;

  /// For each group: its key (its path of names, which stays the same
  /// from run to run), its depth, and how many tasks, sandboxes and drawn
  /// things it holds at any depth.
  function info(groups, nodes) {
    const byPath = new Map();
    const out = new Map();
    const ordered = [...groups.values()].sort((a, b) => Number(a.id.slice(1)) - Number(b.id.slice(1)));
    for (const g of ordered) {
      const c = chain(groups, g.id);
      const path = c.map((x) => x.name).join(' › ');
      const n = byPath.get(path) || 0;
      byPath.set(path, n + 1);
      out.set(g.id, { key: n ? `${path} #${n + 1}` : path, depth: c.length - 1, leaves: 0, sandboxes: 0, tasks: 0 });
    }
    for (const n of nodes) {
      for (const g of chain(groups, n.group)) {
        const i = out.get(g.id);
        if (n.kind !== 'sandbox') i.tasks++;
        if (!shown(n)) continue;
        i.leaves++;
        if (n.kind === 'sandbox') i.sandboxes++;
      }
    }
    return out;
  }

  /// Groups holding more drawn things than this start closed.
  const OPEN_LIMIT = 40;

  /// Whether a group starts open: when it is outermost and not too big.
  const openByDefault = (i) => i.depth === 0 && i.leaves <= OPEN_LIMIT;

  /// Works out what is drawn. Each drawn task or sandbox is drawn itself,
  /// or as the outermost closed group it is in. A link between two things
  /// drawn as one is inside it, and not drawn. Links that join the same
  /// two drawn things become one drawn edge.
  ///
  /// Returns:
  /// - `owner`: task or sandbox id to the id drawn for it (its own, or a
  ///   group's);
  /// - `closed`: the groups drawn as one box;
  /// - `frames`: the open groups that hold something drawn;
  /// - `contOf`: for each drawn id, and for `f:<group>` of each frame, the
  ///   open group it sits in, or null;
  /// - `edges`: the drawn edges, { id, a, b, label, members }, where each
  ///   member is { e: link, flip } and `flip` says the link's side 0 goes
  ///   from b to a. An edge for one link keeps the link's id and ends.
  function aggregate(groups, nodes, links, isOpen) {
    const owner = new Map();
    const closed = new Set();
    const frames = new Set();
    const contOf = new Map();
    for (const n of nodes) {
      if (!shown(n)) continue;
      const c = chain(groups, n.group);
      const shut = c.find((g) => !isOpen(g.id));
      if (shut) {
        owner.set(n.id, shut.id);
        closed.add(shut.id);
        contOf.set(shut.id, parentOf(groups, shut.id));
      } else {
        owner.set(n.id, n.id);
        contOf.set(n.id, n.group && groups.has(n.group) ? n.group : null);
      }
      for (const g of c) {
        if (!isOpen(g.id)) break;
        frames.add(g.id);
      }
    }
    for (const gid of frames) contOf.set(`f:${gid}`, parentOf(groups, gid));
    const byPair = new Map();
    for (const e of links) {
      const da = owner.get(e.a);
      const db = owner.get(e.b);
      if (!da || !db || da === db) continue;
      const [a, b] = da < db ? [da, db] : [db, da];
      const key = `x:${a}~${b}`;
      let d = byPair.get(key);
      if (!d) {
        d = { id: key, a, b, label: null, members: [] };
        byPair.set(key, d);
      }
      d.members.push({ e, flip: da !== a });
    }
    const edges = [];
    for (const d of byPair.values()) {
      if (d.members.length === 1) {
        const { e } = d.members[0];
        edges.push({ id: e.id, a: owner.get(e.a), b: owner.get(e.b), label: e.label || null, members: [{ e, flip: false }] });
      } else {
        const labels = new Set(d.members.map((m) => m.e.label).filter(Boolean));
        d.label = labels.size === 1 ? [...labels][0] : null;
        edges.push(d);
      }
    }
    return { owner, closed, frames, contOf, edges };
  }

  /// A drawn edge's packets and bytes, as a link's: from a, then from b.
  function counts(d) {
    const c = [0, 0, 0, 0];
    for (const { e, flip } of d.members) {
      const m = flip ? [e.c[2], e.c[3], e.c[0], e.c[1]] : e.c;
      for (let i = 0; i < 4; i++) c[i] += m[i];
    }
    return c;
  }

  /// A drawn edge's packet rate each way, from `rate(link)`, which gives
  /// a link's [from side 0, from side 1].
  function rates(d, rate) {
    const r = [0, 0];
    for (const { e, flip } of d.members) {
      const lr = rate(e);
      r[0] += flip ? lr[1] : lr[0];
      r[1] += flip ? lr[0] : lr[1];
    }
    return r;
  }

  return { chain, parentOf, shown, info, openByDefault, aggregate, counts, rates, OPEN_LIMIT };
})();

if (typeof module === 'object') module.exports = FictionetGroups;
