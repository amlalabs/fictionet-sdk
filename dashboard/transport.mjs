// Watch and packet streams and packet detail requests.
// The caller passes state reducers and status effects, with optional EventSource and fetch implementations.
export function createTransport({ state, setStatus, tick, snapshot, upsertGroup, removeGroup, upsertNode, removeNode, upsertEdge, removeEdge, counters, addEvent }, { EventSource = globalThis.EventSource, fetch = globalThis.fetch } = {}) {
  let events;
  function connect() {
    events = new EventSource('api/watch');
    events.addEventListener('waiting', () => {
      state.connected = true;
      setStatus('waiting', 'Waiting for a world');
    });
    events.addEventListener('snapshot', (e) => snapshot(JSON.parse(e.data)));
    events.addEventListener('group', (e) => upsertGroup(JSON.parse(e.data)));
    events.addEventListener('group_end', (e) => removeGroup(JSON.parse(e.data).id));
    events.addEventListener('node', (e) => upsertNode(JSON.parse(e.data)));
    events.addEventListener('node_end', (e) => removeNode(JSON.parse(e.data).id));
    events.addEventListener('edge', (e) => upsertEdge(JSON.parse(e.data)));
    events.addEventListener('edge_end', (e) => removeEdge(JSON.parse(e.data).id));
    events.addEventListener('counters', (e) => counters(JSON.parse(e.data)));
    events.addEventListener('event', (e) => addEvent(JSON.parse(e.data)));
    events.addEventListener('ended', (e) => {
      tick(JSON.parse(e.data).t);
      state.ended = true;
      setStatus('ended', 'World stopped');
      state.sideDirty = true;
    });
    events.addEventListener('end', () => {
      // The stream is over: do not reconnect to a world that has ended.
      events.close();
      if (!state.ended) setStatus('ended', 'The world closed');
      state.ended = true;
    });
    events.onerror = () => {
      if (!state.ended) setStatus('connecting', 'Reconnecting');
    };
  }

  function packetStream(list, reconnected = () => {}) {
    const source = new EventSource(`api/packets?link=${list}`);
    let opened = false;
    source.addEventListener('open', () => {
      if (opened) reconnected();
      opened = true;
    });
    return source;
  }

  function packet(p, signal) {
    return fetch(`api/packet?link=${p.link}&seq=${p.seq}`, { signal });
  }

  return { connect, packetStream, packet };
}
