//! Four typed observation streams from a run.
//!
//! The integrator installs one [`Observer`] in [`RunOptions`](crate::RunOptions).
//! Every region shares it. [`Interest`] checks whether work is wanted;
//! [`Observation`] borrows the result for delivery:
//!
//! | Stream | Interest | Observation | Contents |
//! |---|---|---|---|
//! | [`Stream::Events`] | `Interest::Event` | `Observation::Event` | Structured service, network and world facts with [`ConnInfo`] and [`Fields`]. |
//! | [`Stream::Packets`] | `Interest::Packet` | `Observation::Packet` | One [`PacketRef`] per interested successful link crossing. |
//! | [`Stream::Keys`] | `Interest::TlsKey` | `Observation::TlsKey` | A [`KeyRef`] with TLS label, client random, secret and optional connection context. |
//! | [`Stream::Topology`] | `Interest::Topology` | `Observation::Topology` | [`TopologyRef`] changes for tasks, groups, hosts, links and connection bindings. |
//!
//! World code names facts with [`Cx::emit`](crate::Cx::emit) and observable links
//! with [`Cx::tap`](crate::Cx::tap). Untapped links offer no packets. Attachments
//! are tapped by their sandbox names; the stdlib taps its named network links.
//! Packet interest borrows the bytes before any copy, clock read or number.
//! Core does no packet copying, decoding or sampling.
//! [`LinkType::Ip`] means IP bytes without a link-layer header. The packet
//! includes its link, tap name, sandbox, sending side and original length.
//! TLS key debug output omits secret bytes. Topology includes link owners, taps
//! and absolute directional counters. Hosts have their own identity, separate
//! from groups.
//!
//! # Interest, identity and order
//!
//! Producers check interest before observation work. [`Cx::emit`](crate::Cx::emit)
//! invokes its builder only for an interested observer. With no observer,
//! observation allocates nothing, reads no clock, increments no sequence and
//! registers no links. Normal runtime state still exists: tasks need identity,
//! and explicit [`Cx::group`](crate::Cx::group) calls allocate group state.
//! Use [`Cx::event_enabled`](crate::Cx::event_enabled) or [`Emitter::enabled`]
//! before building longer-lived event tracking state.
//!
//! [`Stamp`] gives the stream, its sequence from 1, and the run-clock time.
//! A lab uses lab time. Events, keys and topology have separate sequences;
//! each link has its own packet sequence. Packet interest cannot change event
//! numbering. Every interested successful crossing consumes a packet number.
//! A consumer can sample after delivery; core does not sample. Declined
//! crossings consume no numbers.
//!
//! [`TaskId`], [`GroupId`], [`HostId`] and [`LinkId`] are run-scoped identities.
//! Each kind starts at 1. An entity gets its identity when it registers with
//! the run, and that identity is never reused within the run. Link identity
//! comes from the run, not a process-wide counter. Handles carry identity,
//! not a materialized graph.
//!
//! [`Fanout`] unions its children's interest. It filters each delivery for
//! each child using that observation's own interest. Children share stamps,
//! so a child's filtered stream can have gaps. Gaps alone do not imply loss.
//! Event-only observers must decline packets, TLS keys and topology explicitly.
//! Topology interest is fixed when the run starts.
//!
//! # Delivery and loss
//!
//! Delivery is synchronous. Numbering and callbacks are serialized per stream.
//! Different streams may arrive concurrently from different threads, with no
//! ordering between streams. Callbacks run outside cable, network, queue and
//! group locks. Per-link publication order is kept. Topology made during a
//! task poll is staged within bounds and delivered when that poll returns.
//! Observers must return promptly and must not call back into the world.
//! Put I/O on a bounded worker queue.
//!
//! [`Loss`] names the stream, reason, count, optional byte count and optional
//! inclusive sequence range. [`LossReason`] distinguishes a full producer
//! staging buffer, consumer sampling, truncation, retention eviction and a
//! full worker queue. Producers can lose items before assigning a sequence.
//! Consumers must track their own loss as well as loss reported by core.
//!
//! `run.start` emits the seed and clock origin once at zero when interested.
//! [`RunOptions::fields`](crate::RunOptions::fields) adds caller metadata.
//! Fixed inputs, interests, limits and lab scheduling give the same
//! observations and stamps. See [Repeatable runs](crate::guide::running#repeatable-runs).
//! Interactive capture and worker overflow depend on external scheduling.
//!
//! # Consumption
//!
//! Core keeps dispatch, bounded event construction, run clocks, identity,
//! producer hooks and the rustls key adapter. It keeps no history, topology
//! graph, retained keys, packet collection or decoders.
//! Consumers choose their own storage and presentation. Packet inspection
//! is available separately in [`stdlib::dissect`](crate::stdlib::dissect).
//!
//! Services can also offer plaintext output through [`Observer::content`].
//! This opt-in callback is separate from the numbered streams and has no core
//! retention. HTTP supplies entity bytes and their content encoding, TLS supplies
//! its selected certificate chain, and other services supply their output bytes.
//! A [`ContentSink`] receives chunks and a completion marker; a cutoff or a range
//! response does not mark a whole representation complete. Consumers own decoding,
//! limits and any worker queues. Packet policies do not select this content.
//!
//! # Repeats
//!
//! Services emit every occurrence. [`Event::repeat`] marks repeatable facts
//! and their variable detail. Consumers choose how to combine them.

pub use observer::{Content, ContentSink};

mod model;
mod observer;

pub(crate) use model::Origin;
pub use model::{ConnInfo, Event, EventValue, Fields, Level, Sandbox, Transport, float, opt};
pub use observer::{Dispatch, Emitter, Fanout, Metadata, Observation, Observer, Stamp};

#[cfg(all(test, feature = "std"))]
mod tests;

#[cfg(test)]
pub(crate) mod recorder;

pub(crate) mod streams;

pub use streams::*;

pub(crate) mod staging;

/// A short name for a task, from the type of its future: the last two
/// path segments, without closures and generics.
/// `fictionet::stdlib::web::net::pings::{{closure}}` becomes `net::pings`.
/// A name with no path, such as `delay`, stays as it is.
pub fn short_name(full: &str) -> String {
    // Cut generic arguments, which can hold paths of their own.
    let mut depth = 0;
    let mut plain = String::with_capacity(full.len());
    for ch in full.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => plain.push(ch),
            _ => {}
        }
    }
    let parts: Vec<&str> = plain
        .split("::")
        .filter(|p| !p.is_empty() && !p.starts_with('{'))
        .collect();
    let n = parts.len();
    parts[n.saturating_sub(2)..].join("::")
}

#[cfg(test)]
mod names {
    use super::short_name;
    #[test]
    fn names_come_from_the_future_type() {
        async fn pings() {}
        fn name_of<F>(_: &F) -> String {
            short_name(std::any::type_name::<F>())
        }
        assert_eq!(name_of(&pings()), "names_come_from_the_future_type::pings");
        let block = async {};
        assert_eq!(name_of(&block), "names::names_come_from_the_future_type");
    }
}
