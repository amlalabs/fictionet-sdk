use std::sync::Arc;

use fictionet::events::{Interest, Observation, TopologyKind};

/// Whether a packet class needs a viewer on its link.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum When {
    /// Retain from the first observation.
    #[default]
    Always,
    /// Retain packets while a viewer watches the link.
    Watched,
}

/// A separate count, byte and sampling budget for each stream.
#[derive(Clone, Copy, Debug)]
pub struct Class {
    /// The name attached to retained observations.
    pub name: &'static str,
    /// Only packet classes may require a viewer.
    pub when: When,
    /// Maximum retained items per stream.
    pub count: usize,
    /// Maximum retained bytes per stream.
    pub bytes: usize,
    /// Lower ranks are evicted first under the shared byte budget.
    pub rank: usize,
    /// Maximum copied packet bytes. None keeps the whole packet.
    pub snap: Option<usize>,
    /// Items per 100 ms before exponential thinning. None never thins.
    pub burst: Option<u64>,
}

impl Class {
    /// An unthinned class with no count or byte bound.
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            when: When::Always,
            count: usize::MAX,
            bytes: usize::MAX,
            rank: 0,
            snap: None,
            burst: None,
        }
    }
    /// Sets the retained item bound.
    pub const fn count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }
    /// Sets the retained byte bound.
    pub const fn bytes(mut self, bytes: usize) -> Self {
        self.bytes = bytes;
        self
    }
    /// Sets the shared-budget eviction rank. Higher ranks retain priority.
    pub const fn rank(mut self, rank: usize) -> Self {
        self.rank = rank;
        self
    }
    /// Requires a viewer on the packet's link.
    pub const fn watched(mut self) -> Self {
        self.when = When::Watched;
        self
    }
    /// Limits copied bytes per packet.
    pub const fn snap(mut self, snap: usize) -> Self {
        self.snap = Some(snap);
        self
    }
    /// Sets the number of items before thinning in each 100 ms window.
    pub const fn burst(mut self, burst: u64) -> Self {
        self.burst = Some(burst);
        self
    }
}

/// A decision before building, copying, numbering or timing an observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Decline the observation.
    Skip,
    /// Retain in the indexed class.
    Class(usize),
    /// Build an event and sort it at delivery.
    Build,
}

/// Selection and retention, fixed before installing an observer.
pub trait Policy: Send + Sync + 'static {
    /// Classes and their per-stream budgets. The slice must remain fixed.
    fn classes(&self) -> &[Class];
    /// Pure and lock-free. A fanout may call this more than once per item.
    fn admit(&self, interest: Interest<'_>) -> Admit;
    /// Classifies an event admitted with Build. Packets and keys never call this.
    fn sort(&self, observation: &Observation<'_>) -> Option<usize>;
    /// Topology selection, fixed at run start.
    fn topology(&self, kind: TopologyKind) -> bool {
        let _ = kind;
        true
    }
}

impl dyn Policy {
    /// Ordinary events, separate noise, keys, and sampled packets. Sandbox
    /// packets start immediately; other links require a viewer.
    #[expect(
        clippy::should_implement_trait,
        reason = "policy presets return shared trait objects"
    )]
    pub fn default() -> Arc<Self> {
        Arc::new(Standard::default())
    }
    /// Ordinary events and separate noise, for graders.
    pub fn events() -> Arc<Self> {
        Arc::new(Standard {
            classes: default_classes()[..2].to_vec(),
        })
    }
}

pub(crate) const NOISE: crate::Limits = crate::Limits::new(5_000, 2 << 20);

/// Bytes all packet rings share under the default budget.
pub(crate) const PACKET_BYTES: usize = 64 << 20;

/// The default shared budget: the event, noise and key class budgets, plus
/// `PACKET_BYTES` for packets. Packet rings rank lowest, so packet load
/// evicts packets and leaves events and keys alone.
pub(crate) fn default_bytes() -> usize {
    default_classes()
        .iter()
        .take(3)
        .map(|class| class.bytes)
        .sum::<usize>()
        + PACKET_BYTES
}

pub(crate) fn default_classes() -> Vec<Class> {
    vec![
        Class::new("events")
            .count(crate::MAX_EVENTS)
            .bytes(crate::MAX_EVENT_BYTES)
            .rank(1),
        Class::new("noise")
            .count(NOISE.events)
            .bytes(NOISE.bytes)
            .rank(1),
        Class::new("keys").count(20_000).bytes(8 << 20).rank(2),
        Class::new("packets")
            .count(4_096)
            .bytes(8 << 20)
            .snap(65_535)
            .burst(64),
        Class::new("packets")
            .watched()
            .count(4_096)
            .bytes(8 << 20)
            .snap(65_535)
            .burst(64),
    ]
}

pub(crate) struct Standard {
    pub(crate) classes: Vec<Class>,
}
impl Default for Standard {
    fn default() -> Self {
        Self {
            classes: default_classes(),
        }
    }
}
impl Policy for Standard {
    fn classes(&self) -> &[Class] {
        &self.classes
    }
    fn admit(&self, interest: Interest<'_>) -> Admit {
        match interest {
            Interest::Event(..) => Admit::Build,
            Interest::TlsKey(_) if self.classes.len() > 2 => Admit::Class(2),
            Interest::Packet(p) if self.classes.len() > 4 => {
                Admit::Class(if p.sandbox.is_some() { 3 } else { 4 })
            }
            Interest::Topology(_) => Admit::Build,
            _ => Admit::Skip,
        }
    }
    fn sort(&self, observation: &Observation<'_>) -> Option<usize> {
        match observation {
            Observation::Event(e) => Some(usize::from(
                e.repeat_fields().is_some() && self.classes.len() > 1,
            )),
            _ => None,
        }
    }
}

pub(crate) fn watched() -> Arc<dyn Policy> {
    let mut policy = Standard::default();
    policy.classes[3].when = When::Watched;
    Arc::new(policy)
}
