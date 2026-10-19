#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod capture;
mod keys;
mod loss;
mod topology;

#[cfg(feature = "decode")]
mod dashboard;
#[cfg(feature = "decode")]
mod json;
#[cfg(feature = "decode")]
mod value;
#[cfg(feature = "decode")]
mod view;
#[cfg(feature = "decode")]
pub use dashboard::{DashboardHandle, DashboardObserver, DashboardOptions, Session};
#[cfg(feature = "decode")]
pub use value::{Envelope, Value};
#[cfg(all(feature = "native", unix))]
mod endpoint;
#[cfg(all(feature = "native", unix))]
pub use endpoint::{Client, Endpoint, serve};

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod jsonl;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use jsonl::Jsonl;
#[cfg(feature = "tracing")]
mod tracing_bridge;
#[cfg(feature = "tracing")]
pub use tracing_bridge::Tracing;

pub use capture::{CaptureDemand, CapturePolicy, PacketBatch, PacketCopy};
pub use keys::{Key, keylog};
pub use loss::{LossStatus, LossTotal};
pub use topology::{Connection, Group, Host, Link, Task, Topology, TopologyLimits};

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use fictionet::events::{
    Counts, Interest, Limits, LinkId, Loss, LossReason, Memory, Observation, Observer, Stamp,
    Stream, TopologyRef,
};
use fictionet::sync::Mutex;
use fictionet::time::Instant;

use capture::{CaptureFlag, Captures};
use keys::Keys;

/// Count and byte bounds. Zero refuses retention.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Maximum retained items.
    pub count: usize,
    /// Maximum retained bytes.
    pub bytes: usize,
}

/// All collector limits and capture policies.
#[derive(Clone, Debug)]
pub struct Options {
    /// Ordinary event retention; none declines events.
    pub events: Option<Limits>,
    /// Separate retention for repeating network events.
    pub noise: Limits,
    /// Topology count and text limits.
    pub topology: TopologyLimits,
    /// Capture policy for sandbox links.
    pub sandbox_capture: CapturePolicy,
    /// Capture policy for other links.
    pub capture: CapturePolicy,
    /// Maximum bytes copied from each packet.
    pub snap_len: usize,
    /// Per-link packet count and payload byte limits.
    pub packets: Bounds,
    /// Aggregate packet payload byte budget across links.
    pub packet_bytes: usize,
    /// TLS key retention; none declines keys.
    pub keys: Option<Bounds>,
    /// Maximum streams with detailed loss totals. Further loss remains in
    /// `LossStatus::untracked`, grouped by cause without stream identity.
    pub loss_streams: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            events: Some(Limits::default()),
            noise: Limits::new(5000, 2 << 20),
            topology: TopologyLimits::default(),
            sandbox_capture: CapturePolicy::Startup,
            capture: CapturePolicy::Demand,
            snap_len: 65_535,
            packets: Bounds {
                count: 4096,
                bytes: 8 << 20,
            },
            packet_bytes: 64 << 20,
            keys: Some(Bounds {
                count: 20_000,
                bytes: 8 << 20,
            }),
            loss_streams: 4099,
        }
    }
}

/// A bounded collector for one run. Callbacks copy and update state on the
/// caller's thread. Readers own their snapshots and copies.
pub struct Collector {
    options: Options,
    events: Memory,
    flags: ArcSwap<BTreeMap<LinkId, Arc<CaptureFlag>>>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    topology: Topology,
    captures: Captures,
    keys: Keys,
    losses: LossStatus,
    ended: Option<Instant>,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

impl Collector {
    /// Creates a collector before installing it on a run.
    pub fn new(options: Options) -> Self {
        Self {
            events: Memory::with_noise_limits(
                options.events.unwrap_or(Limits::new(0, 0)),
                options.noise,
            ),
            options,
            flags: ArcSwap::from_pointee(BTreeMap::new()),
            state: Mutex::new(State::default()),
        }
    }

    /// The retained event observer, including its grading and cursor methods.
    pub fn events(&self) -> &Memory {
        &self.events
    }
    /// A revisioned, bounded snapshot of current entities.
    pub fn topology(&self) -> Topology {
        self.state.lock().topology.clone()
    }
    /// Live absolute counters for every retained link.
    pub fn counters(&self) -> BTreeMap<LinkId, [Counts; 2]> {
        self.topology().counters()
    }
    /// Retained copies after a copy cursor and the number evicted before them.
    pub fn packets(&self, link: LinkId, after: u64, max: usize) -> PacketBatch {
        self.state
            .lock()
            .captures
            .links
            .get(&link)
            .map_or_else(PacketBatch::default, |c| c.since(after, max))
    }
    /// Retained TLS keys, ordered by stream sequence.
    pub fn keys(&self) -> Vec<Key> {
        self.state.lock().keys.items.iter().cloned().collect()
    }
    /// Retained TLS keys in SSLKEYLOGFILE format.
    pub fn keylog(&self) -> String {
        keylog(&self.keys())
    }
    /// Persistent loss totals, including producer loss.
    pub fn losses(&self) -> LossStatus {
        self.state.lock().losses.clone()
    }
    /// Run end time, when delivery has ended.
    pub fn ended(&self) -> Option<Instant> {
        self.state.lock().ended
    }
    /// Starts or joins demand capture. Off and unknown links return none.
    pub fn capture_demand(&self, link: LinkId) -> Option<CaptureDemand> {
        self.flags.load().get(&link)?.demand()
    }
}

impl Observer for Collector {
    fn enabled(&self, interest: Interest<'_>) -> bool {
        match interest {
            Interest::Event(..) => self.options.events.is_some(),
            Interest::Topology(_) => true,
            Interest::TlsKey(_) => self.options.keys.is_some(),
            Interest::Packet(packet) => {
                let flags = self.flags.load();
                flags.get(&packet.link).map_or(
                    self.options.capture == CapturePolicy::Startup
                        || self.options.sandbox_capture == CapturePolicy::Startup,
                    |flag| flag.enabled(),
                )
            }
        }
    }

    fn observe(&self, stamp: Stamp, item: Observation<'_>) {
        if let Observation::Event(event) = item {
            if self.options.events.is_none() || self.state.lock().ended.is_some() {
                return;
            }
            let before = self.events.dropped();
            self.events.observe(stamp, Observation::Event(event));
            let dropped = self.events.dropped().saturating_sub(before);
            let mut state = self.state.lock();
            let losses = &mut state.losses;
            if dropped > 0 {
                let retained = self
                    .events
                    .after(stamp.seq.saturating_sub(1), 1)
                    .first()
                    .is_some_and(|e| e.seq == stamp.seq);
                let reason = if retained {
                    LossReason::Eviction
                } else {
                    LossReason::Overflow
                };
                losses.event_loss(self.options.loss_streams, reason, dropped);
            }
            if event.is_truncated() {
                losses.record(self.options.loss_streams, stamp, LossReason::Truncation, 0);
            }
            return;
        }
        let mut state = self.state.lock();
        if state.ended.is_some() {
            return;
        }
        let State {
            topology,
            captures,
            keys,
            losses,
            ..
        } = &mut *state;
        match item {
            Observation::TlsKey(key) => {
                if let Some(bounds) = self.options.keys {
                    keys.push(stamp, key, bounds, losses, self.options.loss_streams);
                }
            }
            Observation::Packet(packet) => {
                if self.enabled(Interest::Packet(fictionet::events::PacketMeta {
                    link: packet.link,
                    side: packet.side,
                    len: packet.len,
                    link_type: packet.link_type,
                })) {
                    captures.push(stamp, packet, &self.options, losses);
                }
            }
            Observation::Topology(item) => {
                let link = match &item {
                    TopologyRef::LinkAdded { link, sandbox, .. } => Some((
                        *link,
                        Some(if sandbox.is_some() {
                            self.options.sandbox_capture
                        } else {
                            self.options.capture
                        }),
                    )),
                    TopologyRef::LinkRemoved { link, .. } => {
                        captures.retired(*link);
                        Some((*link, None))
                    }
                    _ => None,
                };
                topology.apply(
                    stamp,
                    item,
                    self.options.topology,
                    losses,
                    self.options.loss_streams,
                );
                if let Some((id, policy)) = link {
                    let mut flags = (**self.flags.load()).clone();
                    if let Some(policy) = policy.filter(|_| topology.links.contains_key(&id)) {
                        flags.insert(id, Arc::new(CaptureFlag::new(policy)));
                        if policy != CapturePolicy::Startup {
                            captures.remove(id, losses, self.options.loss_streams);
                        }
                    } else {
                        flags.remove(&id);
                        if policy.is_some() {
                            captures.remove(id, losses, self.options.loss_streams);
                        }
                    }
                    self.flags.store(Arc::new(flags));
                }
            }
            _ => {}
        }
    }

    fn lost(&self, loss: Loss) {
        let mut state = self.state.lock();
        if state.ended.is_some() {
            return;
        }
        if loss.stream == Stream::Topology && loss.count > 0 {
            state.topology.incomplete = true;
            state.topology.revision = state.topology.revision.saturating_add(1);
        }
        state.losses.add(self.options.loss_streams, loss.clone());
        drop(state);
        if loss.stream == Stream::Events {
            self.events.lost(loss);
        }
    }

    fn end(&self, at: Instant) {
        let mut state = self.state.lock();
        if state.ended.is_none() {
            state.ended = Some(at);
            drop(state);
            self.events.end(at);
        }
    }
}

#[cfg(test)]
mod tests;
