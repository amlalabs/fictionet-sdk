Each component exports `mount(root, services, options) -> dispose`.
Mount is synchronous; asynchronous imports and requests stay inside its lifetime.
The composition mounts visible panels and disposes them when hidden. Components
render text and elements only under `root` and release listeners, subscriptions,
sockets, timers, observers and animation frames when disposed, including work
that resolves after disposal.

A browser allows six HTTP/1.1 connections to one origin, so a page holds at
most three long-lived streams: one watch, one state stream for every topic,
and one packet stream. Components never open their own watch or state stream;
they subscribe through `services`. Everything else is a short request.

`services.transport` owns same-origin authenticated requests and console sockets.
`services.watch()` returns a source with the page's one watch stream: the latest
snapshot and the changes since, then live events. Close it when done.
`services.connect(graph)` binds that watch to a graph state (see `state.mjs`).
`services.state(path, onSnapshot, onError)` subscribes to a state topic and
returns an unsubscribe function; snapshots have `{revision, at, value, status}`.
It fetches a replacement snapshot when a delta arrives, since deltas are the
author's. A topic stays on the stream after its panel closes, so switching
panels never reopens the stream. `services.selection` holds explicit host, node, link, event,
connection and request identities. `services.theme` has `current()` and
`subscribe(listener) -> unsubscribe`. `services.format` contains text formatters
for bytes, counts and run time. `services.dom` has the DOM helpers `scoped`,
`listen`, `icon` and `reconcile`, which updates a keyed list in place so live
rows keep their place and focus. `services.moment(element)` applies the shared
story moment style. `services.runTime()` is the run's clock in seconds.
`services.stopped()` is true once the header says Stopped; a load that fails
then should say the run has stopped rather than report the failed request.

A world panel's content is padded and scrolls when it is taller than its
place. Its own pieces can use the page's classes: `eyebrow` (add `accent` for
the accent color) for a small label, `note` for a muted remark, `section` for
a part with a rule above it, `pill` (add `outline` or `marked`) for a badge,
and `switch` for a two-state button holding a `switch-track` with a
`switch-knob`, then its label.

Options are the panel description from `/api/page`, with any explicit composition
settings. World state comes from services, never module globals or DOM lookups
outside the root. Libraries load through dynamic imports inside mount; a failed
import reports the library name and `cargo xtask demo libraries` in that panel.
