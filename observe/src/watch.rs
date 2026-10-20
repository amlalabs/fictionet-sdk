//! Link watches: one link's captured copies, decoded in order and kept for
//! the packet list, the detail pane and the capture download.
//!
//! Readers decode. A watch decodes when a session pumps it, on that
//! session's thread, never in an observer callback. Locks are taken in this
//! order: the watch set, then one watch, then the collector.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fictionet::events::{LinkId, Side};
use fictionet::sync::Mutex;

use crate::dashboard::Shared;
use crate::decode::pcap;
use crate::json::{self, Object};
use crate::{Bounds, CaptureDemand, Collector, Dissector, KeyLine, Registry};

/// How many decoded packets a watch keeps.
pub(crate) const ROWS: usize = 4096;
/// How many bytes of decoded packets a watch keeps: the packets, their
/// list lines and their details.
pub(crate) const ROW_BYTES: usize = 32 << 20;
/// How many copies one pump decodes, so that a session gets back to its
/// client even while the link floods.
const PUMP_BATCH: usize = 1024;
/// How long a watch's rows are kept after its last subscriber leaves.
pub(crate) const LINGER: Duration = Duration::from_secs(60);
/// The size of each piece of a capture download.
const EXPORT_CHUNK: usize = 1 << 18;

/// A decoded packet.
struct Row {
    /// Numbers the rows of a watch from 1.
    seq: u64,
    /// Decode order across all watches, for the aggregate budget.
    order: u64,
    /// When it crossed, in microseconds since the Unix epoch, or since
    /// the run started in a lab.
    micros: u64,
    /// Its length on the link.
    len: usize,
    data: Arc<[u8]>,
    /// The packet list's line, as JSON.
    summary: String,
    /// The detail pane, as JSON.
    detail: String,
}

impl Row {
    fn bytes(&self) -> usize {
        self.data.len() + self.summary.len() + self.detail.len()
    }
}

/// One watched link, shared by everyone watching it.
pub(crate) struct LinkWatch {
    id: LinkId,
    /// `packets` streams following this link now.
    subscribers: AtomicUsize,
    inner: Mutex<Inner>,
}

struct Inner {
    /// Capture demand, while someone subscribes.
    demand: Option<CaptureDemand>,
    /// The last capture copy decoded.
    cursor: u64,
    /// Copies evicted before the next decoded row.
    evicted: u64,
    next_row: u64,
    dissector: Dissector,
    rows: VecDeque<Row>,
    row_bytes: usize,
    max_rows: usize,
    max_bytes: usize,
    /// When the last subscriber left, once a caller has said what time it is.
    released: Option<Instant>,
    released_order: u64,
    /// The link's ends and label, as the `link` event shows them.
    link: String,
    /// TLS keys taken from the collector so far, bounded by count and bytes.
    keys: VecDeque<KeyLine>,
    key_bytes: usize,
    /// The collector's key sequence taken so far.
    keys_seen: u64,
    /// The set forgot this watch. It decodes nothing more.
    gone: bool,
}

fn key_size(key: &KeyLine) -> usize {
    size_of::<KeyLine>() + key.label.len() + key.client_random.len() + key.secret.len()
}

/// A capture download in progress. It holds the rows it was made from,
/// without copying their bytes, and writes the file one piece at a time.
pub(crate) struct Export {
    header: Option<Vec<u8>>,
    rows: VecDeque<(u64, usize, Arc<[u8]>)>,
}

impl Export {
    /// The next piece of the file, and whether it is the last.
    pub(crate) fn next_chunk(&mut self) -> (Vec<u8>, bool) {
        let mut out = self.header.take().unwrap_or_default();
        while out.len() < EXPORT_CHUNK
            && let Some((micros, len, data)) = self.rows.pop_front()
        {
            pcap::packet(&mut out, micros, len, &data);
        }
        (out, self.rows.is_empty())
    }
}

impl LinkWatch {
    fn new(id: LinkId, link: String, registry: Registry) -> Self {
        Self {
            id,
            subscribers: AtomicUsize::new(0),
            inner: Mutex::new(Inner {
                demand: None,
                cursor: 0,
                evicted: 0,
                next_row: 1,
                dissector: Dissector::with_registry(registry),
                rows: VecDeque::new(),
                row_bytes: 0,
                max_rows: ROWS,
                max_bytes: ROW_BYTES,
                released: None,
                released_order: 0,
                link,
                keys: VecDeque::new(),
                key_bytes: 0,
                keys_seen: 0,
                gone: false,
            }),
        }
    }

    /// The link this watch decodes.
    pub(crate) fn id(&self) -> LinkId {
        self.id
    }

    /// The link's ends, for the start of a packet stream.
    pub(crate) fn describe(&self) -> String {
        self.inner.lock().link.clone()
    }

    fn subscribe(&self, collector: &Collector) {
        let mut inner = self.inner.lock();
        if self.subscribers.fetch_add(1, Ordering::SeqCst) == 0 {
            inner.demand = collector.capture_demand(self.id);
            inner.released = None;
        }
    }

    fn unsubscribe(&self, now: Option<Instant>, order: u64) {
        let mut inner = self.inner.lock();
        if self.subscribers.fetch_sub(1, Ordering::SeqCst) == 1 {
            inner.demand = None;
            inner.released = now;
            inner.released_order = order;
        }
    }

    /// The last release's order, if idle. Called under the set's lock, so
    /// no subscription arrives between checking and eviction.
    fn idle_order(&self) -> Option<u64> {
        let inner = self.inner.lock();
        (self.subscribers.load(Ordering::SeqCst) == 0).then_some(inner.released_order)
    }

    /// Whether the last subscriber left at least `LINGER` before `now`. An
    /// idle watch whose release time is not known yet starts its linger now.
    fn expired(&self, now: Instant) -> bool {
        let mut inner = self.inner.lock();
        if self.subscribers.load(Ordering::SeqCst) != 0 {
            return false;
        }
        let released = *inner.released.get_or_insert(now);
        now.saturating_duration_since(released) >= LINGER
    }

    /// Drops every row, for a watch the set no longer keeps.
    fn forget(&self, total: &AtomicUsize) {
        let mut inner = self.inner.lock();
        inner.gone = true;
        inner.rows.clear();
        total.fetch_sub(std::mem::take(&mut inner.row_bytes), Ordering::Relaxed);
        inner.demand = None;
    }

    fn front_order(&self) -> Option<u64> {
        self.inner.lock().rows.front().map(|r| r.order)
    }

    /// Drops this watch's oldest rows while they are older than `before`
    /// and the set is over `budget`.
    fn evict_front(&self, before: u64, total: &AtomicUsize, budget: usize) {
        let mut inner = self.inner.lock();
        while total.load(Ordering::Relaxed) > budget
            && inner.rows.front().is_some_and(|r| r.order <= before)
        {
            let old = inner.rows.pop_front().expect("front row");
            inner.row_bytes -= old.bytes();
            total.fetch_sub(old.bytes(), Ordering::Relaxed);
        }
    }

    /// Decodes copies captured since the last call, up to a batch. Returns
    /// whether it caught up with the capture.
    pub(crate) fn pump(&self, shared: &Shared) -> bool {
        let collector = &shared.collector;
        let watches = &shared.watches;
        let wall = shared.wall().map_or(0, |d| d.as_micros() as u64);
        let mut inner = self.inner.lock();
        let mut done = 0;
        let mut drained = inner.gone;
        while !inner.gone && done < PUMP_BATCH {
            let batch = collector.packets(self.id, inner.cursor, 512);
            if batch.missed > 0 {
                inner.evicted += batch.missed;
                inner.dissector.lost();
            }
            inner.cursor = batch.cursor;
            if batch.packets.is_empty() {
                drained = true;
                break;
            }
            done += batch.packets.len();
            inner.take_keys(collector, watches.keys);
            let inner = &mut *inner;
            for copy in batch.packets {
                if copy.skipped > 0 {
                    inner.dissector.lost();
                }
                let seq = inner.next_row;
                inner.next_row += 1;
                let at = copy.stamp.at.since_start();
                let side = match copy.side {
                    Side::A => 0,
                    Side::B => 1,
                };
                let keys = inner.keys.make_contiguous();
                let mut decoded = inner.dissector.decode(&copy.bytes, keys);
                decoded.tags.sort_unstable();
                decoded.tags.dedup();
                let summary = Object::new()
                    .num("seq", seq)
                    .secs("t", at)
                    .num("side", side)
                    .num("len", copy.original_len)
                    .num("skipped", copy.skipped)
                    .num("evicted", std::mem::take(&mut inner.evicted))
                    .str("src", &decoded.src)
                    .str("dst", &decoded.dst)
                    .str("proto", &decoded.proto)
                    .str("info", &decoded.info)
                    .raw(
                        "tags",
                        &json::array(decoded.tags.iter().map(|t| json::quote(t))),
                    )
                    .done();
                let mut detail = Object::new()
                    .num("seq", seq)
                    .secs("t", at)
                    .num("side", side)
                    .num("len", copy.original_len)
                    .done();
                // The layers and buffers go straight into the object, before
                // its closing brace.
                detail.pop();
                detail.push_str(",\"layers\":");
                decoded.write_layers(&mut detail);
                detail.push_str(",\"buffers\":");
                decoded.write_buffers(&mut detail, &copy.bytes);
                detail.push('}');
                let row = Row {
                    seq,
                    order: watches.order.fetch_add(1, Ordering::Relaxed),
                    micros: wall.saturating_add(at.as_micros() as u64),
                    len: copy.original_len,
                    data: copy.bytes,
                    summary,
                    detail,
                };
                inner.row_bytes += row.bytes();
                watches.total.fetch_add(row.bytes(), Ordering::Relaxed);
                inner.rows.push_back(row);
                while inner.rows.len() > inner.max_rows || inner.row_bytes > inner.max_bytes {
                    let Some(old) = inner.rows.pop_front() else {
                        break;
                    };
                    inner.row_bytes -= old.bytes();
                    watches.total.fetch_sub(old.bytes(), Ordering::Relaxed);
                }
            }
        }
        drop(inner);
        watches.enforce();
        drained
    }

    /// Packet list lines after row `after`, at most `max`, and how many
    /// rows before them are no longer kept.
    pub(crate) fn rows_after(&self, after: u64, max: usize) -> (u64, Vec<(u64, String)>) {
        let inner = self.inner.lock();
        let first = inner.rows.front().map_or(inner.next_row, |r| r.seq);
        let missed = first.saturating_sub(after.saturating_add(1));
        let skip = inner.rows.partition_point(|r| r.seq <= after);
        let rows = inner
            .rows
            .iter()
            .skip(skip)
            .take(max)
            .map(|r| (r.seq, r.summary.clone()))
            .collect();
        (missed, rows)
    }

    /// The detail of row `seq`, if it is still kept.
    pub(crate) fn detail(&self, seq: u64) -> Option<String> {
        let inner = self.inner.lock();
        let at = inner.rows.partition_point(|r| r.seq < seq);
        inner
            .rows
            .get(at)
            .filter(|r| r.seq == seq)
            .map(|r| r.detail.clone())
    }

    /// Every kept row as a pcapng download, with this watch's cached TLS
    /// keys and the collector's current keys, each line once.
    pub(crate) fn export(&self, collector: &Collector) -> Export {
        let (rows, mut keys) = {
            let inner = self.inner.lock();
            let rows: VecDeque<_> = inner
                .rows
                .iter()
                .map(|r| (r.micros, r.len, r.data.clone()))
                .collect();
            (rows, inner.keys.iter().cloned().collect::<Vec<_>>())
        };
        keys.extend(collector.keys().iter().map(KeyLine::from));
        let mut seen = BTreeSet::new();
        let mut keylog = String::new();
        for key in keys.iter().filter(|k| {
            seen.insert((
                k.label.as_str(),
                k.client_random.as_slice(),
                k.secret.as_slice(),
            ))
        }) {
            crate::keys::push_keylog_line(&mut keylog, &key.label, &key.client_random, &key.secret);
        }
        let mut header = Vec::new();
        pcap::start(&mut header, keylog.as_bytes());
        Export {
            header: Some(header),
            rows,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_limits(&self, rows: usize, bytes: usize) {
        let mut inner = self.inner.lock();
        inner.max_rows = rows;
        inner.max_bytes = bytes;
    }

    #[cfg(test)]
    pub(crate) fn cached_keys(&self) -> usize {
        self.inner.lock().keys.len()
    }
}

impl Inner {
    /// Takes the keys the collector added since last time. The collector
    /// forgets its oldest keys past its bounds, and so does this cache.
    fn take_keys(&mut self, collector: &Collector, bounds: Bounds) {
        for key in collector.keys_after(self.keys_seen) {
            self.keys_seen = key.stamp.seq;
            let line = KeyLine::from(&key);
            let size = key_size(&line);
            if bounds.count == 0 || size > bounds.bytes {
                continue;
            }
            while self.keys.len() >= bounds.count || self.key_bytes > bounds.bytes - size {
                let old = self.keys.pop_front().expect("key cache");
                self.key_bytes -= key_size(&old);
            }
            self.key_bytes += size;
            self.keys.push_back(line);
        }
    }
}

/// One `packets` stream's hold on a watch. While any is held, the link's
/// capture demand is held too.
pub(crate) struct Subscription {
    watch: Arc<LinkWatch>,
    order: Arc<AtomicU64>,
    released: bool,
}

impl Subscription {
    pub(crate) fn watch(&self) -> &Arc<LinkWatch> {
        &self.watch
    }

    /// Releases the hold, starting the linger at `now`.
    pub(crate) fn release(mut self, now: Instant) {
        self.released = true;
        self.watch
            .unsubscribe(Some(now), self.order.fetch_add(1, Ordering::Relaxed));
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if !self.released {
            self.watch
                .unsubscribe(None, self.order.fetch_add(1, Ordering::Relaxed));
        }
    }
}

/// The link watches of one dashboard, shared by the subscribers of each link.
pub(crate) struct Watches {
    state: Mutex<BTreeMap<u64, Arc<LinkWatch>>>,
    registry: Registry,
    limit: usize,
    budget: usize,
    /// Bounds of each watch's key cache.
    keys: Bounds,
    /// Decoded row bytes across all watches.
    total: AtomicUsize,
    /// Orders rows and releases across all watches.
    order: Arc<AtomicU64>,
}

impl Watches {
    pub(crate) fn new(registry: Registry, limit: usize, budget: usize, keys: Bounds) -> Self {
        Self {
            state: Mutex::new(BTreeMap::new()),
            registry,
            limit,
            budget,
            keys,
            total: AtomicUsize::new(0),
            order: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Finds or creates the watch of link `number` and subscribes to it.
    /// `link` describes a link the collector knows, if it is not watched yet.
    pub(crate) fn acquire(
        &self,
        collector: &Collector,
        number: u64,
        now: Instant,
        link: impl FnOnce() -> Option<(LinkId, String)>,
    ) -> Result<Subscription, &'static str> {
        self.reap(now);
        let mut state = self.state.lock();
        let watch = if let Some(watch) = state.get(&number) {
            watch.clone()
        } else {
            let (id, link) = link().ok_or("no such link")?;
            let active = state.values().filter(|w| w.idle_order().is_none()).count();
            if active >= self.limit {
                return Err("this world has too many watched links");
            }
            while state.len() >= self.limit {
                let Some((_, victim)) = state
                    .iter()
                    .filter_map(|(number, w)| w.idle_order().map(|order| (order, *number)))
                    .min()
                else {
                    break;
                };
                if let Some(old) = state.remove(&victim) {
                    old.forget(&self.total);
                }
            }
            let watch = Arc::new(LinkWatch::new(id, link, self.registry.clone()));
            state.insert(number, watch.clone());
            watch
        };
        watch.subscribe(collector);
        Ok(Subscription {
            watch,
            order: self.order.clone(),
            released: false,
        })
    }

    /// The watch of link `number`, if one is kept after reaping at `now`.
    pub(crate) fn existing(&self, number: u64, now: Instant) -> Option<Arc<LinkWatch>> {
        self.reap(now);
        self.state.lock().get(&number).cloned()
    }

    /// Forgets watches whose last subscriber left a minute before `now`.
    pub(crate) fn reap(&self, now: Instant) {
        self.state.lock().retain(|_, watch| {
            let expired = watch.expired(now);
            if expired {
                watch.forget(&self.total);
            }
            !expired
        });
    }

    /// Brings the decoded rows of all watches within the aggregate budget:
    /// idle watches go first, longest idle first, then the oldest rows.
    fn enforce(&self) {
        if self.total.load(Ordering::Relaxed) <= self.budget {
            return;
        }
        let mut state = self.state.lock();
        while self.total.load(Ordering::Relaxed) > self.budget {
            let Some((_, victim)) = state
                .iter()
                .filter_map(|(number, w)| w.idle_order().map(|order| (order, *number)))
                .min()
            else {
                break;
            };
            if let Some(old) = state.remove(&victim) {
                old.forget(&self.total);
            }
        }
        while self.total.load(Ordering::Relaxed) > self.budget {
            let mut fronts: Vec<_> = state
                .values()
                .filter_map(|w| w.front_order().map(|order| (order, w)))
                .collect();
            fronts.sort_unstable_by_key(|(order, _)| *order);
            let Some(&(_, oldest)) = fronts.first() else {
                break;
            };
            let before = fronts.get(1).map_or(u64::MAX, |(order, _)| *order);
            oldest.evict_front(before, &self.total, self.budget);
        }
    }

    #[cfg(test)]
    pub(crate) fn kept(&self) -> Vec<u64> {
        self.state.lock().keys().copied().collect()
    }

    #[cfg(test)]
    pub(crate) fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests;
