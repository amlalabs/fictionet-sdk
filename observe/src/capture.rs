use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fictionet::events::{LinkId, LinkType, LossReason, PacketRef, Side, Stamp};

use crate::ring::{Kept, Ring};
use crate::{LossStatus, Options};

impl Kept for PacketCopy {
    fn stamp(&self) -> Stamp {
        self.stamp
    }
    fn size(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Default)]
pub(crate) struct Demand {
    readers: AtomicUsize,
}
impl Demand {
    pub(crate) fn enabled(&self) -> bool {
        self.readers.load(Ordering::Relaxed) != 0
    }
    pub(crate) fn take(self: &Arc<Self>) -> Option<CaptureDemand> {
        self.readers
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()?;
        Some(CaptureDemand(self.clone()))
    }
}

/// A reader's demand on one link. Dropping the last handle stops watched classes.
pub struct CaptureDemand(Arc<Demand>);
impl Drop for CaptureDemand {
    fn drop(&mut self) {
        self.0.readers.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A bounded copy of a packet crossing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketCopy {
    /// Original stream sequence and run time.
    pub stamp: Stamp,
    /// Policy class index.
    pub class: usize,
    /// Tap name at the crossing.
    pub tap: Arc<str>,
    /// Sending end.
    pub side: Side,
    /// Original packet length before snap truncation.
    pub original_len: usize,
    /// Packet framing.
    pub link_type: LinkType,
    /// Retained bytes.
    pub bytes: Arc<[u8]>,
    /// Packets sampled out in this class since its preceding copy.
    pub skipped: u64,
    /// Ledger omissions through this copy, used to break decoder continuity.
    pub(crate) omissions: u64,
}

/// Captures merged by the core's per-link sequence.
#[derive(Clone, Debug, Default)]
pub struct PacketBatch {
    /// Total evictions per class. Readers compare these with their previous totals.
    pub evicted: Vec<(usize, u64)>,
    /// Sequence for the next read, including gaps when no copies remain.
    pub cursor: u64,
    /// Retained copies, bounded by the read limit and class limits.
    pub packets: Vec<PacketCopy>,
}

#[derive(Default)]
pub(crate) struct Capture {
    pub(crate) sandbox: Option<String>,
    pub(crate) rings: BTreeMap<usize, Ring<PacketCopy>>,
    removed: Option<u64>,
    pub(crate) crossings: Option<u64>,
    tap: Option<Arc<str>>,
}

impl Capture {
    pub(crate) fn since(&self, after: u64, max: usize) -> PacketBatch {
        let batch = crate::ring::batch(self.rings.values(), Some(after), max);
        PacketBatch {
            evicted: self.rings.keys().copied().zip(batch.evicted).collect(),
            cursor: batch.events.last().map_or(
                if max == 0 {
                    after
                } else {
                    after.max(batch.last)
                },
                |p| p.stamp.seq,
            ),
            packets: batch.events,
        }
    }
}

#[derive(Default)]
pub(crate) struct Captures {
    pub(crate) links: BTreeMap<LinkId, Capture>,
    pub(crate) bytes: usize,
    order: u64,
    randoms: BTreeMap<[u8; 32], usize>,
    #[cfg(test)]
    pub(crate) compared_windows: AtomicUsize,
}

impl Captures {
    pub(crate) fn has_random(&self, random: &[u8]) -> bool {
        self.randoms.contains_key(random)
    }

    pub(crate) fn retired(&mut self, id: LinkId, crossings: u64) {
        self.order = self.order.saturating_add(1);
        if let Some(capture) = self.links.get_mut(&id) {
            capture.removed = Some(self.order);
            capture.crossings = Some(crossings);
        }
    }

    fn oldest_removed(&self) -> Option<LinkId> {
        self.links
            .iter()
            .filter_map(|(id, c)| c.removed.map(|order| (*id, order)))
            .min_by_key(|(_, order)| *order)
            .map(|(id, _)| id)
    }

    pub(crate) fn largest(&self, classes: &[crate::Class]) -> Option<(LinkId, usize, usize, bool)> {
        self.links
            .iter()
            .flat_map(|(link, capture)| {
                capture
                    .rings
                    .iter()
                    .filter(|(_, ring)| !ring.items.is_empty())
                    .map(move |(class, ring)| {
                        (*link, *class, ring.bytes, capture.removed.is_some())
                    })
            })
            .max_by_key(|(link, class, bytes, removed)| {
                (
                    *removed,
                    std::cmp::Reverse(classes[*class].rank),
                    *bytes,
                    std::cmp::Reverse((*link, *class)),
                )
            })
    }

    pub(crate) fn evict(
        &mut self,
        id: LinkId,
        class: usize,
        losses: &mut LossStatus,
        limit: usize,
    ) {
        let ring = self
            .links
            .get_mut(&id)
            .expect("capture link")
            .rings
            .get_mut(&class)
            .expect("capture class");
        if let Some(old) = ring.evict() {
            update_randoms(
                &mut self.randoms,
                &old.bytes,
                false,
                #[cfg(test)]
                &self.compared_windows,
            );
            self.bytes -= old.bytes.len();
            losses.record(
                limit,
                old.stamp,
                Some(old.class),
                LossReason::Eviction,
                old.bytes.len(),
            );
        }
    }

    fn remove(&mut self, id: LinkId, losses: &mut LossStatus, limit: usize) {
        if let Some(capture) = self.links.remove(&id) {
            for ring in capture.rings.into_values() {
                self.bytes -= ring.bytes;
                for old in ring.items {
                    update_randoms(
                        &mut self.randoms,
                        &old.bytes,
                        false,
                        #[cfg(test)]
                        &self.compared_windows,
                    );
                    losses.record(
                        limit,
                        old.stamp,
                        Some(old.class),
                        LossReason::Eviction,
                        old.bytes.len(),
                    );
                }
            }
        }
    }

    pub(crate) fn push(
        &mut self,
        stamp: Stamp,
        packet: PacketRef<'_>,
        index: usize,
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
                Some(index),
                LossReason::Overflow,
                packet.len,
            );
            return;
        }
        let class = &options.policy.classes()[index];
        let capture = self.links.entry(packet.link).or_default();
        if capture.sandbox.is_none() {
            capture.sandbox = packet.sandbox.map(str::to_owned);
        }
        let ring = capture.rings.entry(index).or_default();
        if !ring.admit(stamp, class.burst) {
            losses.record(
                options.loss_streams,
                stamp,
                Some(index),
                LossReason::Sampling,
                packet.len,
            );
            return;
        }
        let len = packet.bytes.len().min(class.snap.unwrap_or(usize::MAX));
        if len < packet.len {
            losses.record(
                options.loss_streams,
                stamp,
                Some(index),
                LossReason::Truncation,
                packet.len - len,
            );
        }
        if class.count == 0 || len > class.bytes || len > options.bytes {
            ring.skipped = 0;
            losses.record(
                options.loss_streams,
                stamp,
                Some(index),
                LossReason::Overflow,
                len,
            );
            return;
        }
        ring.make_room(
            len,
            class.count,
            class.bytes,
            |_| 0,
            |old| {
                update_randoms(
                    &mut self.randoms,
                    &old.bytes,
                    false,
                    #[cfg(test)]
                    &self.compared_windows,
                );
                self.bytes -= old.bytes.len();
                losses.record(
                    options.loss_streams,
                    old.stamp,
                    Some(old.class),
                    LossReason::Eviction,
                    old.bytes.len(),
                );
            },
        );
        if capture.tap.as_deref() != Some(packet.tap) {
            capture.tap = Some(packet.tap.into());
        }
        let tap = capture.tap.as_ref().expect("capture tap").clone();
        let copy = PacketCopy {
            stamp,
            class: index,
            tap,
            side: packet.side,
            original_len: packet.len,
            link_type: packet.link_type,
            bytes: packet.bytes[..len].into(),
            skipped: std::mem::take(&mut ring.skipped),
            omissions: losses.omissions(stamp.stream, index),
        };
        update_randoms(
            &mut self.randoms,
            &copy.bytes,
            true,
            #[cfg(test)]
            &self.compared_windows,
        );
        ring.push(copy);
        self.bytes += len;
    }
}

// Index packet-local ClientHello prefixes, including truncated handshakes.
fn update_randoms(
    randoms: &mut BTreeMap<[u8; 32], usize>,
    bytes: &[u8],
    retain: bool,
    #[cfg(test)] compared_windows: &AtomicUsize,
) {
    for window in bytes.windows(38) {
        #[cfg(test)]
        compared_windows.fetch_add(1, Ordering::Relaxed);
        let length = u32::from_be_bytes([0, window[1], window[2], window[3]]);
        if window[0] != 1 || length < 34 || window[4] != 3 || window[5] > 3 {
            continue;
        }
        let random: [u8; 32] = window[6..].try_into().expect("client random");
        if retain {
            *randoms.entry(random).or_default() += 1;
        } else {
            let count = randoms.get_mut(&random).expect("retained client random");
            *count -= 1;
            if *count == 0 {
                randoms.remove(&random);
            }
        }
    }
}
