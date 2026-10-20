// The page's long-lived streams, shared by every component. A browser allows
// six HTTP/1.1 connections to one origin, so a page holds at most three
// streams: one watch, one state stream for every topic, and one for packets.

const queue = globalThis.queueMicrotask || ((callback) => Promise.resolve().then(callback));

// Watch events that change what a late subscriber must be told. Counters
// are absolute, so only the latest is kept for a late subscriber.
const RECORDED = ['waiting', 'snapshot', 'host', 'host_end', 'group', 'group_end', 'node', 'node_end', 'edge', 'edge_end', 'status', 'event', 'gap', 'ended', 'end', 'world_error'];
const FORWARDED = [...RECORDED, 'counters', 'open', 'error'];

/// One watch stream for the page. `subscribe()` returns a source with the
/// stream's events: first the latest snapshot and the changes since it, then
/// live events. `close()` on a source detaches it; the stream itself stays
/// open until `dispose()`.
export function createWatchHub(transport, { limit = 5000 } = {}) {
  const subscribers = new Set();
  let upstream, unbind = () => {}, history = [], counters = null;

  function open() {
    history = [];
    counters = null;
    const source = upstream = transport.watch();
    const removers = FORWARDED.map((name) => {
      const listener = (event) => {
        if (name === 'counters') counters = event.data;
        else if (RECORDED.includes(name)) {
          if (name === 'snapshot') {
            history = [];
            counters = null;
          }
          history.push([name, event.data]);
        }
        for (const subscriber of subscribers) if (!subscriber.pending) subscriber.emit(name, event.data);
        // A long run would make a late subscriber replay too much: start again
        // from a fresh snapshot instead.
        if (history.length > limit) reopen();
      };
      source.addEventListener(name, listener);
      return () => source.removeEventListener(name, listener);
    });
    unbind = () => removers.forEach((remove) => remove());
  }
  function reopen() {
    unbind();
    unbind = () => {};
    upstream?.close();
    upstream = null;
    if (subscribers.size) open();
  }

  return {
    subscribe() {
      const source = new EventTarget();
      source.pending = true;
      source.emit = (name, data) => {
        const event = new Event(name);
        event.data = data;
        source.dispatchEvent(event);
      };
      source.close = () => { subscribers.delete(source); };
      subscribers.add(source);
      if (!upstream) open();
      // Replay once the caller has added its listeners.
      queue(() => {
        if (!subscribers.has(source)) return;
        source.pending = false;
        for (const [name, data] of history) source.emit(name, data);
        if (counters !== null) source.emit('counters', counters);
      });
      return source;
    },
    dispose() {
      subscribers.clear();
      unbind();
      unbind = () => {};
      upstream?.close();
      upstream = null;
    },
  };
}

/// Every state topic the page shows, on one stream. `subscribe(id, onSnapshot,
/// onError)` returns an unsubscribe function. The stream sends a topic's
/// snapshot after each change.
///
/// Opening a panel must not cost the page its stream: the stream reopens only
/// for a topic it does not carry yet. A topic whose last panel closed stays on
/// the stream, kept current, until nothing listens or the stream would carry
/// more than the server allows. Reopening drops what the old stream had not
/// delivered yet, and the new one can only resend it if it connects.
export function createStateHub(transport, { most = 64, stopped = () => false } = {}) {
  const topics = new Map();
  let stream, carried = '', unbind = () => {}, scheduled = false;

  function deliver(topic, snapshot) {
    if (snapshot.revision < (topic.latest?.revision ?? 0)) return;
    topic.latest = snapshot;
    for (const listener of topic.listeners) listener.onSnapshot(snapshot);
  }
  function fail(topic, error) {
    for (const listener of topic.listeners) listener.onError(error);
  }
  function reopen() {
    scheduled = false;
    const listened = [...topics.values()].some((topic) => topic.listeners.size);
    if (!listened || topics.size > most) for (const [id, topic] of topics) if (!topic.listeners.size) topics.delete(id);
    const ids = [...topics.keys()].join(',');
    if (stream && ids === carried) return;
    unbind();
    unbind = () => {};
    stream?.close();
    stream = null;
    carried = ids;
    if (!ids) return;
    const cursors = Object.fromEntries([...topics].map(([id, topic]) => [id, topic.latest?.revision]));
    const source = stream = transport.stateStream(cursors);
    const on = (name, callback) => {
      const listener = (event) => callback(JSON.parse(event.data));
      source.addEventListener(name, listener);
      return () => source.removeEventListener(name, listener);
    };
    const removers = [
      on('snapshot', ({ topic: id, ...snapshot }) => { const topic = topics.get(id); if (topic) deliver(topic, snapshot); }),
      // A dropped connection is not a failure: the transport reconnects with
      // the cursors this stream opened with, which are never newer than what
      // the topics hold, so the server sends what changed in between. Only a
      // refusal ends the stream: its topics fail, and a later subscription
      // starts a stream without them.
      on('world_error', ({ error }) => {
        for (const [id, topic] of topics) { fail(topic, new Error(error)); topics.delete(id); }
        stream = null;
        carried = '';
      }),
      // After the run stopped a failed connection will not come back: topics
      // with nothing to show say so and leave, so a panel opened later asks
      // again and hears the same, and the stream stops trying.
      on('error', () => {
        if (!stopped()) return;
        for (const [id, topic] of topics) if (!topic.latest) { fail(topic, new Error('The run has stopped, so its state can no longer be loaded')); topics.delete(id); }
        unbind();
        unbind = () => {};
        source.close();
        stream = null;
        carried = '';
      }),
    ];
    unbind = () => removers.forEach((remove) => remove());
  }
  function schedule() {
    if (scheduled) return;
    scheduled = true;
    queue(reopen);
  }

  return {
    subscribe(id, onSnapshot, onError = () => {}) {
      let topic = topics.get(id);
      if (!topic) {
        topic = { listeners: new Set(), latest: null };
        topics.set(id, topic);
        schedule();
      }
      const listener = { onSnapshot, onError };
      topic.listeners.add(listener);
      if (topic.latest) onSnapshot(topic.latest);
      return () => {
        topic.listeners.delete(listener);
        if (topics.get(id) !== topic) return;
        if (![...topics.values()].some((item) => item.listeners.size)) schedule();
      };
    },
    dispose() {
      for (const id of [...topics.keys()]) topics.delete(id);
      reopen();
    },
  };
}
