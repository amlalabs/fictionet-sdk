use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fictionet::events::{LinkId, LinkType, LossReason, PacketRef, Side, Stamp};
use fictionet::time::{Duration, Instant};

use crate::{LossStatus, Options};

/// When a link's packets are retained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CapturePolicy {
    /// Never capture this link.
    Off,
    /// Capture from registration onward.
    Startup,
    /// Capture while at least one demand handle exists.
    #[default]
    Demand,
}

pub(crate) struct CaptureFlag {
    policy: CapturePolicy,
    readers: AtomicUsize,
}

impl CaptureFlag {
    pub(crate) fn new(policy: CapturePolicy) -> Self {
        Self {
            policy,
            readers: AtomicUsize::new(0),
        }
    }
    pub(crate) fn enabled(&self) -> bool {
        self.policy == CapturePolicy::Startup
            || (self.policy == CapturePolicy::Demand && self.readers.load(Ordering::Relaxed) != 0)
    }
    pub(crate) fn demand(self: &Arc<Self>) -> Option<CaptureDemand> {
        if self.policy == CapturePolicy::Off {
            return None;
        }
        self.readers
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()?;
        Some(CaptureDemand(self.clone()))
    }
}

/// A reader's capture demand. Dropping the last handle stops demand capture.
/// It does not keep a world link alive.
pub struct CaptureDemand(Arc<CaptureFlag>);
impl Drop for CaptureDemand {
    fn drop(&mut self) {
        self.0.readers.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A bounded copy of a packet crossing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketCopy {
    /// Cursor counting copies, independent of the stream sequence.
    pub cursor: u64,
    /// Original stream sequence and run time.
    pub stamp: Stamp,
    /// Sending end.
    pub side: Side,
    /// Original packet length before snap truncation.
    pub original_len: usize,
    /// Packet framing.
    pub link_type: LinkType,
    /// Retained bytes.
    pub bytes: Arc<[u8]>,
    /// Packets sampled out since the preceding copy.
    pub skipped: u64,
    pub(crate) order: u64,
}

/// Captures after a copy cursor. Sampling gaps remain in the packet stamps.
#[derive(Clone, Debug, Default)]
pub struct PacketBatch {
    /// Copies evicted between the supplied cursor and the first retained copy.
    pub missed: u64,
    /// Cursor for the next read, including evictions when no copies remain.
    pub cursor: u64,
    /// Retained copies, bounded by the read limit and capture limits.
    pub packets: Vec<PacketCopy>,
}

#[derive(Default)]
pub(crate) struct Capture {
    pub(crate) sandbox: Option<String>,
    copies: VecDeque<PacketCopy>,
    bytes: usize,
    next: u64,
    window: Option<Instant>,
    in_window: u64,
    skipped: u64,
    removed: Option<u64>,
}

impl Capture {
    pub(crate) fn since(&self, after: u64, max: usize) -> PacketBatch {
        let first = self
            .copies
            .front()
            .map_or(self.next.saturating_add(1), |p| p.cursor);
        let packets: Vec<_> = self
            .copies
            .iter()
            .filter(|p| p.cursor > after)
            .take(max)
            .cloned()
            .collect();
        PacketBatch {
            missed: first.saturating_sub(after.saturating_add(1)),
            cursor: packets
                .last()
                .map_or(after.max(first.saturating_sub(1)), |p| p.cursor),
            packets,
        }
    }
}

fn keep(k: u64) -> bool {
    k < 64 || k.is_multiple_of(1u64 << (k / 64).min(30))
}

#[derive(Default)]
pub(crate) struct Captures {
    pub(crate) links: BTreeMap<LinkId, Capture>,
    bytes: usize,
    order: u64,
}

impl Captures {
    pub(crate) fn retired(&mut self, id: LinkId) {
        self.order = self.order.saturating_add(1);
        if let Some(capture) = self.links.get_mut(&id) {
            capture.removed = Some(self.order);
        }
    }

    fn oldest_removed(&self) -> Option<LinkId> {
        self.links
            .iter()
            .filter_map(|(id, c)| c.removed.map(|order| (*id, order)))
            .min_by_key(|(_, order)| *order)
            .map(|(id, _)| id)
    }

    fn oldest(&self) -> Option<LinkId> {
        self.links
            .iter()
            .filter_map(|(id, c)| {
                c.copies
                    .front()
                    .map(|p| (*id, (c.removed.is_none(), c.removed.unwrap_or(p.order))))
            })
            .min_by_key(|(_, order)| *order)
            .map(|(id, _)| id)
    }

    fn evict(&mut self, id: LinkId, losses: &mut LossStatus, loss_streams: usize) {
        let capture = self.links.get_mut(&id).expect("capture link");
        if let Some(old) = capture.copies.pop_front() {
            capture.bytes -= old.bytes.len();
            self.bytes -= old.bytes.len();
            losses.record(
                loss_streams,
                old.stamp,
                LossReason::Eviction,
                old.bytes.len(),
            );
        }
    }

    pub(crate) fn remove(&mut self, id: LinkId, losses: &mut LossStatus, loss_streams: usize) {
        if let Some(capture) = self.links.remove(&id) {
            self.bytes -= capture.bytes;
            for old in capture.copies {
                losses.record(
                    loss_streams,
                    old.stamp,
                    LossReason::Eviction,
                    old.bytes.len(),
                );
            }
        }
    }

    pub(crate) fn push(
        &mut self,
        stamp: Stamp,
        packet: PacketRef<'_>,
        options: &Options,
        losses: &mut LossStatus,
    ) {
        if !self.links.contains_key(&packet.link)
            && self.links.len() >= options.topology.links
            && let Some(id) = self.oldest_removed()
        {
            self.remove(id, losses, options.loss_streams);
        }
        if !self.links.contains_key(&packet.link) && self.links.len() >= options.topology.links {
            losses.record(
                options.loss_streams,
                stamp,
                LossReason::Overflow,
                packet.len,
            );
            return;
        }
        let capture = self.links.entry(packet.link).or_default();
        let start = capture.window.unwrap_or(Instant::ZERO);
        if stamp.at.since_start().saturating_sub(start.since_start()) >= Duration::from_millis(100)
        {
            capture.window = Some(stamp.at);
            capture.in_window = 0;
        }
        let index = capture.in_window;
        capture.in_window = capture.in_window.saturating_add(1);
        if !keep(index) {
            capture.skipped = capture.skipped.saturating_add(1);
            losses.record(
                options.loss_streams,
                stamp,
                LossReason::Sampling,
                packet.len,
            );
            return;
        }
        let len = packet.bytes.len().min(options.snap_len);
        capture.next = capture.next.saturating_add(1);
        if len < packet.len {
            losses.record(
                options.loss_streams,
                stamp,
                LossReason::Truncation,
                packet.len - len,
            );
        }
        if options.packets.count == 0 || len > options.packets.bytes || len > options.packet_bytes {
            capture.skipped = 0;
            while !self.links[&packet.link].copies.is_empty() {
                self.evict(packet.link, losses, options.loss_streams);
            }
            if len > options.packet_bytes {
                while let Some(id) = self.oldest() {
                    self.evict(id, losses, options.loss_streams);
                }
            }
            losses.record(options.loss_streams, stamp, LossReason::Eviction, len);
            return;
        }
        self.order = self.order.saturating_add(1);
        let copy = PacketCopy {
            cursor: capture.next,
            stamp,
            side: packet.side,
            original_len: packet.len,
            link_type: packet.link_type,
            bytes: packet.bytes[..len].into(),
            skipped: std::mem::take(&mut capture.skipped),
            order: self.order,
        };
        while self.links[&packet.link].copies.len() >= options.packets.count
            || self.links[&packet.link].bytes > options.packets.bytes - len
        {
            self.evict(packet.link, losses, options.loss_streams);
        }
        while self.bytes > options.packet_bytes - len {
            let oldest = self.oldest().expect("aggregate capture budget");
            self.evict(oldest, losses, options.loss_streams);
        }
        let capture = self.links.get_mut(&packet.link).expect("capture link");
        capture.bytes += len;
        self.bytes += len;
        capture.copies.push_back(copy);
    }
}
