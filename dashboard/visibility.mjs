// The page declares the sandboxes it draws. Administrative attachments still run.
export function declaredSandbox(hosts, name) {
  return !hosts.length || hosts.some((host) => (host.sandbox || host.name) === name);
}

export function pageGraph(state, hosts) {
  function visible(node) {
    const seen = new Set();
    while (node && !seen.has(node.id)) {
      seen.add(node.id);
      const sandbox = node.kind === 'sandbox' ? node.name : node.sandbox?.name;
      if (sandbox && !declaredSandbox(hosts, sandbox)) return false;
      node = state.nodes.get(node.parent);
    }
    return true;
  }
  const nodes = new Map([...state.nodes].filter(([, node]) => visible(node)));
  const edges = new Map([...state.edges].filter(([, edge]) => nodes.has(edge.a) && nodes.has(edge.b)));
  const events = state.events.filter((event) => (!event.sandbox || declaredSandbox(hosts, event.sandbox.name || event.sandbox)) && (!event.node || nodes.has(event.node)));
  const used = new Set([...nodes.values()].map((node) => node.group).filter(Boolean));
  for (const id of used) {
    const parent = state.groups.get(id)?.parent;
    if (parent) used.add(parent);
  }
  const groups = new Map([...state.groups].filter(([id]) => used.has(id)));
  const declaredHosts = new Map([...state.hosts].filter(([, host]) => !host.sandbox || declaredSandbox(hosts, host.sandbox)));
  return { ...state, nodes, edges, events, groups, hosts: declaredHosts };
}
