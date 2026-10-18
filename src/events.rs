//! Optional observation of facts emitted by services, networks and world code.
//!
//! An [`Event`] has a source, kind, summary, [`Level`], [`ConnInfo`] and JSON
//! [`Fields`]. Integrators install an [`Observer`] before execution through
//! [`RunOptions`](crate::RunOptions): none, [`Memory`], native `Jsonl`,
//! [`Aggregate`], dashboard retention, or their own implementation. [`Fanout`]
//! combines destinations. Regions share the run's immutable observer.
//!
//! ```
//! use std::sync::Arc;
//! use fictionet::{RunOptions, Seed, block_on, lab};
//! use fictionet::events::{Aggregate, Memory};
//! let evidence = Arc::new(Memory::default());
//! let options = RunOptions::new(Seed::from_u64(7))
//!     .observer(Arc::new(Aggregate::new(evidence.clone())));
//! block_on(lab(options, |fcx| async move {
//!     fcx.emit("modbus", "write_register", |event| event
//!         .summary("register 40001 = 900")
//!         .field("register", 40001u32).field("value", 900u32));
//!     Ok(())
//! }))?;
//! assert_eq!(evidence.checked_of("modbus", "write_register")?[0].u64("value"), Some(900));
//! # Ok::<(), fictionet::Error>(())
//! ```
//!
//! # Delivery and retention
//!
//! [`Cx::emit`](crate::Cx::emit) checks interest before invoking its builder.
//! With no observer, recording does no allocation, formatting, clock read,
//! task lookup or sequence increment. Longer-lived service tracking uses
//! [`Cx::event_enabled`](crate::Cx::event_enabled) or a connection's [`Emitter`].
//! Interested observers receive a borrowed event synchronously, in order, and
//! must return promptly without calling back into the world.
//!
//! The dispatch assigns [`Stamp`] sequence numbers and run-clock timestamps
//! before fan-out. Filters can leave gaps; gaps alone do not imply loss.
//! `run.start` is emitted once at zero, with the seed and clock origin.
//! [`RunOptions::fields`](crate::RunOptions::fields) adds caller metadata.
//! Fixed inputs, observer configuration and lab scheduling produce repeatable
//! evidence; see [Repeatable runs](crate::guide::running#repeatable-runs).
//!
//! [`Memory`] owns count- and byte-bounded history. Its default reserves separate
//! event and network-noise budgets, so a flood cannot evict unrelated facts.
//! Oldest events in each budget are evicted first, and loss remains visible
//! through [`Memory::dropped`]. Graders use
//! [`Memory::checked_of`] or [`Memory::checked_all`] to reject incomplete
//! evidence. Reads neither flush nor change retained events. Dashboard clients
//! can attach late only to history explicitly installed with
//! [`RunOptions::event_history`](crate::RunOptions::event_history).
//!
//! Native `Jsonl` keeps the event JSON Lines format and enqueues events within
//! count and byte limits. Its worker performs serialization and I/O. Call its
//! `finish` method outside the run to drain output and check errors. Worker
//! scheduling can affect overflow; synchronous [`Memory`] supplies lab evidence.
//!
//! # Repeats
//!
//! Services emit every occurrence. [`Event::repeat`] marks facts such as a
//! blocked packet or network drop and identifies variable detail, such as the
//! destination port. An optional [`Aggregate`] wraps a destination, counts
//! repeats within bounded run-time windows, delivering the first occurrence
//! immediately. Summaries record first and last
//! sequence references and numeric detail ranges. Reads cannot close windows.
//! Ordinary events, window expiry on the next emission, capacity pressure and
//! run end deliver pending summaries in sequence order. Without aggregation,
//! an observer receives each fact without summary fields.
//!
//! Aggregation bounds pending facts; retention and exporter queues have their
//! own bounds. Unlimited distinct traffic can still exhaust finite history.
//! Byte budgets include owned allocations and charge shared connection data
//! for each retained copy. They exclude spare collection capacity and copies
//! held by readers, so they are retention budgets, not process-memory limits.

mod aggregate;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
mod jsonl;
mod memory;
mod model;
mod observer;

pub use aggregate::Aggregate;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub use jsonl::Jsonl;
#[cfg(feature = "observe")]
pub(crate) use memory::DisplayBatch;
pub use memory::{Incomplete, Limits, Memory};
pub(crate) use model::Origin;
pub use model::{ConnInfo, Event, EventValue, Fields, Level, Sandbox, Transport, float, opt};
pub use observer::{Dispatch, Emitter, Fanout, Metadata, Observation, Observer, Stamp};

/// Default number of ordinary events retained by [`Memory`], separate from noise.
pub const MAX_EVENTS: usize = 50_000;
/// Default ordinary event bytes, as counted by [`Event::size`], separate from noise.
pub const MAX_EVENT_BYTES: usize = 16 << 20;

#[cfg(all(test, feature = "std"))]
mod tests;
