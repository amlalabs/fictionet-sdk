// Shared explicit identities. A timestamp alone never selects a captured flow.
export function createSelection() {
  let value = Object.freeze({ host: null, node: null, links: Object.freeze([]), event: null, connection: null, request: null });
  const listeners = new Set();
  return {
    get: () => value,
    set(patch) {
      for (const key of Object.keys(patch)) {
        if (!Object.hasOwn(value, key)) throw new Error(`Unknown selection field: ${key}`);
      }
      value = Object.freeze({ ...value, ...patch, links: Object.freeze([...(patch.links ?? value.links)]) });
      for (const listener of listeners) listener(value);
    },
    subscribe(listener) {
      listeners.add(listener);
      listener(value);
      return () => listeners.delete(listener);
    },
  };
}
