//! Watching one link: the copies its tap makes, decoded in order, kept for
//! the packet list, the detail pane and the capture download.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use super::decode::Dissector;
use super::json::{self, Object};
use super::view::{edge_id, task_id};
use crate::lock;
use crate::sys::{Instant, UNIX_EPOCH};
use crate::watch::{Graph, KeyLine, Meter, TapGuard};

/// How many decoded packets a watch keeps.
const ROWS: usize = 4096;
/// How many bytes of decoded packets a watch keeps: the packets, their
/// list lines and their details.
pub(crate) const ROW_BYTES: usize = 32 << 20;
/// How many copies one call to [`LinkWatch::pump`] decodes, so that a
/// session gets back to its observer even while the link floods.
const PUMP_BATCH: usize = 1024;

/// A decoded packet.
struct Row {
    /// Numbers the rows of a watch from 1.
    seq: u64,
    /// When it was copied, in microseconds since the Unix epoch.
    micros: u64,
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
///
/// It holds its world weakly, so a world that ends is freed even while the
/// watch is kept. It copies packets only while a subscriber is there.
pub(crate) struct LinkWatch {
    graph: Weak<Graph>,
    id: u64,
    meter: Weak<Meter>,
    /// `packets` streams following this link now.
    subscribers: AtomicUsize,
    inner: Mutex<Inner>,
}

struct Inner {
    /// The tap, while someone subscribes.
    guard: Option<TapGuard>,
    /// The last copy taken from the tap.
    after: u64,
    next_row: u64,
    dissector: Dissector,
    rows: VecDeque<Row>,
    row_bytes: usize,
    /// When the last subscriber left.
    released: Instant,
    /// The node at each end, for the browser.
    ends: [String; 2],
    label: Option<String>,
    /// The world's TLS keys seen so far, and how many the world had added
    /// when they were taken.
    keys: VecDeque<KeyLine>,
    keys_seen: u64,
}

/// One `packets` stream's hold on a watch. While any is held, the link's
/// packets are copied.
pub(crate) struct Subscription(Arc<LinkWatch>);

impl Drop for Subscription {
    fn drop(&mut self) {
        let mut inner = lock(&self.0.inner);
        if self.0.subscribers.fetch_sub(1, Ordering::SeqCst) == 1 {
            inner.guard = None;
            inner.released = Instant::now();
            drop(inner);
            if let Some(graph) = self.0.graph.upgrade() {
                let _ = super::reap_later(&graph);
            }
        }
    }
}

impl LinkWatch {
    /// A watch of link `id`, if the graph has it. It copies nothing until
    /// someone subscribes.
    pub(crate) fn start(graph: &Arc<Graph>, id: u64) -> Option<LinkWatch> {
        let (meter, ends, label) = {
            let s = graph.state();
            let link = s.links.get(&id)?;
            let meter = link.meter.upgrade()?;
            let end = |side: usize| match (side, &link.sandbox) {
                (1, Some(_)) => format!("s{id}"),
                _ => task_id(if link.owners[side] != 0 {
                    link.owners[side]
                } else {
                    link.creator
                }),
            };
            (
                meter,
                [end(0), end(1)],
                link.label.as_deref().map(str::to_owned),
            )
        };
        Some(LinkWatch {
            graph: Arc::downgrade(graph),
            id,
            meter: Arc::downgrade(&meter),
            subscribers: AtomicUsize::new(0),
            inner: Mutex::new(Inner {
                guard: None,
                after: 0,
                next_row: 1,
                dissector: Dissector::with_registry(lock(&graph.protocols).clone()),
                rows: VecDeque::new(),
                row_bytes: 0,
                released: Instant::now(),
                ends,
                label,
                keys: VecDeque::new(),
                keys_seen: 0,
            }),
        })
    }

    /// Starts copying the link's packets, until the returned subscription
    /// is dropped.
    pub(crate) fn subscribe(self: &Arc<Self>) -> Subscription {
        let mut inner = lock(&self.inner);
        if self.subscribers.fetch_add(1, Ordering::SeqCst) == 0
            && let Some(meter) = self.meter.upgrade()
            && let Some(graph) = self.graph.upgrade()
        {
            inner.guard = Some(meter.watch(&graph.environment));
            inner.after = 0;
        }
        Subscription(self.clone())
    }

    /// Whether this watch may be forgotten: it has no subscriber, and the last
    /// left more than `linger` ago.
    pub(crate) fn idle_for(&self, linger: std::time::Duration) -> bool {
        // Under the lock that subscribing and leaving take, so a subscriber
        // that is just arriving is counted.
        let inner = lock(&self.inner);
        self.subscribers.load(Ordering::SeqCst) == 0 && inner.released.elapsed() >= linger
    }

    pub(crate) fn graph(&self) -> Option<Arc<Graph>> {
        self.graph.upgrade()
    }

    /// Whether both ends of the link are gone.
    pub(crate) fn closed(&self) -> bool {
        self.meter.strong_count() == 0
    }

    /// The link's ends, for the start of a packet stream.
    pub(crate) fn describe(&self) -> String {
        let inner = lock(&self.inner);
        Object::new()
            .str("id", &edge_id(self.id))
            .str("a", &inner.ends[0])
            .str("b", &inner.ends[1])
            .opt_str("label", inner.label.as_deref())
            .done()
    }

    /// Decodes copies made since the last call, up to a batch.
    pub(crate) fn pump(&self) {
        let Some(graph) = self.graph.upgrade() else {
            return;
        };
        let mut inner = lock(&self.inner);
        let mut done = 0;
        while done < PUMP_BATCH {
            let Some(guard) = &inner.guard else { return };
            let copies = guard.tap.since(inner.after, 512);
            if copies.is_empty() {
                return;
            }
            done += copies.len();
            {
                // Take the keys added since last time. The world forgets
                // its oldest keys past a limit, and so does this.
                let s = graph.state();
                let new = s.keys_added.saturating_sub(inner.keys_seen) as usize;
                let skip = s.keys.len().saturating_sub(new);
                let fresh: Vec<KeyLine> = s.keys.iter().skip(skip).cloned().collect();
                inner.keys_seen = s.keys_added;
                drop(s);
                inner.keys.extend(fresh);
                let excess = inner.keys.len().saturating_sub(crate::watch::MAX_KEYS);
                inner.keys.drain(..excess);
            }
            let inner = &mut *inner;
            let keys = inner.keys.make_contiguous();
            for copy in copies {
                inner.after = copy.seq;
                let seq = inner.next_row;
                inner.next_row += 1;
                let at = copy.at.since_start();
                let micros = (graph.start_wall + at)
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_micros() as u64);
                let mut decoded = inner.dissector.decode(&copy.data, keys);
                decoded.tags.sort_unstable();
                decoded.tags.dedup();
                let summary = Object::new()
                    .num("seq", seq)
                    .secs("t", at)
                    .num("side", copy.side)
                    .num("len", copy.data.len())
                    .num("skipped", copy.skipped)
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
                    .num("side", copy.side)
                    .num("len", copy.data.len())
                    .done();
                // The layers and buffers go straight into the object, before
                // its closing brace.
                detail.pop();
                detail.push_str(",\"layers\":");
                decoded.write_layers(&mut detail);
                detail.push_str(",\"buffers\":");
                decoded.write_buffers(&mut detail, &copy.data);
                detail.push('}');
                let row = Row {
                    seq,
                    micros,
                    data: copy.data.clone(),
                    summary,
                    detail,
                };
                inner.row_bytes += row.bytes();
                inner.rows.push_back(row);
                while inner.rows.len() > ROWS || inner.row_bytes > ROW_BYTES {
                    let Some(old) = inner.rows.pop_front() else {
                        break;
                    };
                    inner.row_bytes -= old.bytes();
                }
            }
        }
    }

    /// Packet list lines after row `after`, at most `max`.
    pub(crate) fn rows_after(&self, after: u64, max: usize) -> Vec<(u64, String)> {
        let inner = lock(&self.inner);
        let skip = inner
            .rows
            .iter()
            .position(|r| r.seq > after)
            .unwrap_or(inner.rows.len());
        inner
            .rows
            .iter()
            .skip(skip)
            .take(max)
            .map(|r| (r.seq, r.summary.clone()))
            .collect()
    }

    /// The detail of row `seq`, if it is still kept.
    pub(crate) fn detail(&self, seq: u64) -> Option<String> {
        let inner = lock(&self.inner);
        inner
            .rows
            .iter()
            .find(|r| r.seq == seq)
            .map(|r| r.detail.clone())
    }

    /// Every kept packet as a pcapng file, with the world's TLS keys in it,
    /// so Wireshark opens it decrypted.
    pub(crate) fn pcapng(&self) -> Vec<u8> {
        let keys = self.graph.upgrade().map(|g| keylog(&g)).unwrap_or_default();
        let inner = lock(&self.inner);
        let packets: Vec<(u64, &[u8])> =
            inner.rows.iter().map(|r| (r.micros, &r.data[..])).collect();
        super::pcap::pcapng(&packets, keys.as_bytes())
    }
}

/// The world's TLS secrets in the `SSLKEYLOGFILE` format.
pub(crate) fn keylog(graph: &Graph) -> String {
    let s = graph.state();
    let mut out = String::new();
    for k in &s.keys {
        out.push_str(&k.label);
        out.push(' ');
        out.push_str(&hex(&k.client_random));
        out.push(' ');
        out.push_str(&hex(&k.secret));
        out.push('\n');
    }
    out
}

pub(crate) fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    push_hex(&mut s, b);
    s
}

/// Appends `b` in lowercase hex, two digits a byte.
pub(crate) fn push_hex(out: &mut String, b: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.reserve(b.len() * 2);
    for &x in b {
        out.push(DIGITS[(x >> 4) as usize] as char);
        out.push(DIGITS[(x & 15) as usize] as char);
    }
}
