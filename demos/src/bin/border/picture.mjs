// What the world pane shows, derived only from the route state and the
// run's Border view.

// The route the picture draws: normal or hijacked, and whether the
// impostor answers at the bank's address.
export function route(state) {
  return {
    hijacked: state?.mode === 'hijack',
    impostor: state?.impostor !== false,
    revision: state?.revision ?? null,
  };
}

// The newest time the password reached the impostor, or null.
export function stolen(view) {
  const moment = view?.moments?.rows?.findLast((m) => m.password);
  return moment ? { event: moment.event, at: moment.at_ms } : null;
}

// The newest rows first, at most `limit`: who sent what to whom.
export function rows(view, limit = 6) {
  return [...(view?.rows?.rows || [])]
    .sort((a, b) => b.at_ms - a.at_ms || b.event - a.event)
    .slice(0, limit)
    .map((r) => ({ id: r.event, at: r.at_ms, who: r.to ? `${r.from} → ${r.to}` : r.from, what: r.what, tone: r.tone || '' }));
}

// Run time as minutes and seconds.
export const clock = (ms) => {
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
};
