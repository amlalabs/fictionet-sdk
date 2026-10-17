//! Events: everything a world reports about itself, kept by the run
//! whether or not anyone reads it.
//!
//! An [`Event`] is one fact: the source that saw it (`"dns"`, `"http"`,
//! `"lan"`, `"modbus"`), its kind (`"query"`, `"request"`, `"drop"`), a
//! one-line summary, a [`Level`], the connection it came from
//! ([`ConnInfo`]), and named [`Fields`] whose values are JSON. Services,
//! the network and the core's own pieces (a [bottleneck] that drops a
//! packet, a [router] that loses a route, a LAN) all record events, and so
//! can world code:
//!
//! ```
//! # #[cfg(feature = "std")]
//! # {
//! use fictionet::events::{Event, Level};
//! # fictionet::block_on(fictionet::run(fictionet::Seed::random(), |fcx| async move {
//! fcx.record(Event::new("modbus", "write_register")
//!     .summary("register 40001 = 900")
//!     .level(Level::Alarm)
//!     .field("register", 40001u32)
//!     .field("value", 900u32));
//! let events = fcx.events().of("modbus", "write_register");
//! assert_eq!(events[0].u64("value"), Some(900));
//! # Ok(()) }))?;
//! # }
//! # Ok::<(), fictionet::Error>(())
//! ```
//!
//! # The event log
//!
//! Every run keeps an [`EventLog`], from its first moment to its end,
//! with no sink to set. Recording numbers each event (`seq`, from 1, with
//! no gaps) and dates it on the run's clock ([`Cx::now`]), never the
//! host's. In a lab, repeatability depends on the world's inputs and clock
//! use; see [Repeatable runs](crate::running#repeatable-runs), including
//! the HTTP/2 exception.
//! The log is bounded: it holds the latest [`MAX_EVENTS`] events, and at
//! most [`MAX_EVENT_BYTES`] of them ([`Event::size`]). Past either limit
//! the oldest go first. An event larger than its part's byte limit is
//! numbered but not kept, without evicting other events. Every reader
//! that missed some is told how many, with an `events.dropped` event in
//! their place ([`EventLog::after`]), including gaps from rejected events.
//!
//! [`Net::start`](crate::stdlib::net::Net::start) records `run.start`, with
//! the seed and clock origin. Neither [`run`](crate::run) nor
//! [`lab`](crate::lab) emits it automatically. A world built from lower-level
//! pieces calls `fcx.events().start(&fcx, Fields::new())` itself. The event
//! log reports what happened; it is not a recording of every input needed
//! to replay a real run.
//!
//! # Repeats
//!
//! Some events come once per packet: a packet the network refuses
//! (`net.blocked`), or one a LAN, a router or a [bottleneck] drops
//! (`drop`). The sandbox decides how many of those there are, so an agent
//! that scans every port or floods a link would otherwise fill the log
//! and push out the events a grader reads. Such events are recorded with
//! [`Cx::record_repeat`], which counts them instead:
//!
//! - Repeats are alike when their source, kind, connection and fields
//!   match. Fields that change with every packet, such as a destination
//!   port or a length, go in the `detail` given beside the event, and do
//!   not tell repeats apart.
//! - The first of a run of alike repeats is recorded as it comes, with its
//!   detail and the field `count` set to 1. For the next
//!   [`REPEAT_WINDOW`] on the run's clock, repeats of it are only counted.
//!   When the window has passed, the first event recorded after it, or the
//!   run's end, records one more event for them: the same source, kind,
//!   connection and fields, `count` repeats, and for each detail field
//!   that is a number, its lowest and highest values as `[low, high]`.
//!   The sum of `count` over alike events is how many repeats there were.
//! - Repeats are kept apart from every other event, within their own
//!   bounds: the latest [`MAX_REPEATS`] of them, and at most
//!   [`MAX_REPEAT_BYTES`]. Past either, the oldest repeat goes first. A
//!   flood of repeats never pushes out another event, and other events
//!   never push out repeats. A reader that missed some is told as for any
//!   other event: an `events.dropped` event stands where they were.
//! - Open windows have separate bounds: 1,024 windows and
//!   [`MAX_OPEN_REPEAT_BYTES`] for their keys, first events and numeric
//!   detail ranges. To make room, the oldest windows record their counts
//!   early. A repeat too large for a window is recorded individually with
//!   `count` set to 1, subject to the repeat history's limits.
//!
//! While its windows fit, a flood costs at most two events per second for
//! each distinct kind of repeat, and never costs the run a service's
//! event, an HTTP request, a DNS query, a TLS handshake or a connection's
//! open and close.
//!
//! Everything that reads events reads this log:
//!
//! - observers such as `fictionet dashboard` and `fictionet observe
//!   watch`, which see what the log still holds when they connect, then
//!   every new event as it comes (see [`observe`](crate::observe#events));
//! - a JSON Lines file, one event per line, for a grader that reads it
//!   after the run ([`EventLog::to_file`]);
//! - callbacks in the same process ([`EventLog::subscribe`]);
//! - a grader or a test in the same process, which reads the log itself,
//!   during the run or after it ([`EventLog::all`] and [`EventLog::wait`]).
//!
//! A reader that starts late misses nothing the log still holds: a file
//! or a callback set halfway through a run first gets what the log kept,
//! then the rest as it is recorded. Live callbacks receive even events
//! too large to retain. File sinks still apply their own queue limits.
//!
//! Native real runs with `std` write files on a helper thread with a bounded
//! queue. In browsers, labs and builds without `std`, sinks write and flush
//! synchronously in the subscription's drainer, in event order, without
//! writer-queue overflow or writer scheduling affecting the log. A lab's
//! `run.start.wall` is null; real runs record their wall date. Attach a sink
//! before recording begins to retain events beyond the in-memory log's limits.
//!
//! # What it costs
//!
//! Byte budgets charge owned capacities and shared connection metadata
//! in full for each retained copy, with estimated allocation overhead.
//! They exclude spare capacity in history queues and window indexes,
//! static strings, temporary allocations while recording or reading, and
//! copies held by readers, callbacks, or pending subscription deliveries.
//! These are retention budgets, not a process-memory limit.
//!
//! Recording takes the event the caller built, looks up the task that
//! recorded it, and appends it to the log under one lock. Each subscription
//! queues replay and live events in sequence order. One caller drains that
//! queue, invoking callbacks one at a time outside the log and delivery locks.
//! Reentrant or concurrent recording leaves queued callbacks to the active
//! drainer, which may run in a different task or thread from the recorder.
//! Callbacks must return quickly and never block. See [`EventLog::subscribe`].
//! The `sites` group of the performance suite (`cargo bench
//! --bench services -- sites`) measures the cost on HTTPS requests, which
//! record one `http.request` event each. On a busy 24-core machine, a
//! median of three runs took 9.5 µs of CPU per HTTP/1.1 request from ten
//! sandboxes, against 7.9 µs before every run kept its events, and 12.9 µs
//! per HTTP/2 request against 11.5 µs. Most of it is building the event:
//! its headers and fields are about 25 allocations.
//!
//! # Why "event"
//!
//! Fictionet used to call one thing four names: the journal's entries,
//! the graph's notes, the dashboard's "Events", and custom events from
//! world code. They were the same fact (who saw what, when, from which
//! connection), so now they are one type with one name. "Event" is the
//! word the dashboard and world code already used, and it says what the
//! thing is: something that happened at a time. "Note" now means only a
//! line of a decoded packet's layer ([`Layer::note`]), and the log that
//! holds events is the event log.
//!
//! [bottleneck]: crate::stdlib::bottleneck
//! [router]: crate::stdlib::route::router
//! [`Cx::now`]: crate::Cx::now
//! [`Cx::record_repeat`]: crate::Cx::record_repeat
//! [`Layer::note`]: crate::observe::Layer::note

mod log;
mod model;
mod repeat;
mod sink;
mod store;

pub use log::EventLog;
pub(crate) use model::Origin;
pub use model::{ConnInfo, Event, Fields, Level, Sandbox, Transport, float, opt};
pub(crate) use store::Store;

/// How many events a run's log holds. Past this, the oldest are dropped.
pub const MAX_EVENTS: usize = 50_000;
/// How many bytes of events a run's log holds, as [`Event::size`] counts
/// them. Past this, the oldest are dropped. A larger event is not kept.
pub const MAX_EVENT_BYTES: usize = 16 << 20;
/// How many [repeats](self#repeats) a run's log holds, beside its other
/// events. Past this, the oldest repeats are dropped.
pub const MAX_REPEATS: usize = 5_000;
/// How many bytes of [repeats](self#repeats) a run's log holds, beside its
/// other events. Past this, the oldest repeats are dropped. A larger
/// repeat is not kept.
pub const MAX_REPEAT_BYTES: usize = 2 << 20;
/// How many bytes open [repeat windows](self#repeats) hold, separately
/// from the recorded repeats. Counts close early to stay within this
/// budget. A repeat too large for a window is recorded individually.
pub const MAX_OPEN_REPEAT_BYTES: usize = 2 << 20;
/// How long, on the run's clock, repeats of an event are counted before
/// the log records their count. See [Repeats](self#repeats).
pub const REPEAT_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(all(test, feature = "std"))]
mod tests;
