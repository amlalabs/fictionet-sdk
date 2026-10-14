//! Watching one link: the copies its tap makes, decoded in order, kept for
//! the packet list, the detail pane and the capture download.

use fictionet::sync::Mutex;
use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use super::decode::Dissector;
use super::json::{self, Object};
use super::view::{edge_id, task_id};
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
        let mut inner = self.0.inner.lock();
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
                dissector: Dissector::with_registry(graph.protocols.lock().clone()),
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
        let mut inner = self.inner.lock();
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
        let inner = self.inner.lock();
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
        let inner = self.inner.lock();
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
        let mut inner = self.inner.lock();
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
        let inner = self.inner.lock();
        let skip = inner.rows.partition_point(|r| r.seq <= after);
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
        let inner = self.inner.lock();
        inner
            .rows
            .iter()
            .find(|r| r.seq == seq)
            .map(|r| r.detail.clone())
    }

    /// Every kept packet as a pcapng file, with the watch's cached TLS keys
    /// and the world's current keys, so Wireshark can decrypt it.
    pub(crate) fn pcapng(&self) -> Vec<u8> {
        let (rows, mut keys) = {
            let inner = self.inner.lock();
            let rows: Vec<_> = inner
                .rows
                .iter()
                .map(|r| (r.micros, r.data.clone()))
                .collect();
            let keys: Vec<_> = inner.keys.iter().cloned().collect();
            (rows, keys)
        };
        // Snapshot the world separately: never hold both locks for export.
        if let Some(graph) = self.graph.upgrade() {
            keys.extend(graph.state().keys.iter().cloned());
        }
        let mut seen = BTreeSet::new();
        let keys = keylog_lines(keys.iter().filter(|k| {
            seen.insert((
                k.label.as_str(),
                k.client_random.as_slice(),
                k.secret.as_slice(),
            ))
        }));
        let packets: Vec<(u64, &[u8])> = rows
            .iter()
            .map(|(micros, data)| (*micros, &data[..]))
            .collect();
        super::pcap::pcapng(&packets, keys.as_bytes())
    }
}

/// The world's TLS secrets in the `SSLKEYLOGFILE` format.
pub(crate) fn keylog(graph: &Graph) -> String {
    let s = graph.state();
    keylog_lines(&s.keys)
}

fn keylog_lines<'a>(keys: impl IntoIterator<Item = &'a KeyLine>) -> String {
    let mut out = String::new();
    for k in keys {
        out.push_str(&k.label);
        out.push(' ');
        super::json::push_hex(&mut out, &k.client_random);
        out.push(' ');
        super::json::push_hex(&mut out, &k.secret);
        out.push('\n');
    }
    out
}

/// Renders bytes as lowercase hexadecimal, with two digits per byte.
pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    super::json::push_hex(&mut s, b);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::codec::le32;
    use crate::watch::MAX_KEYS;

    fn setup() -> (Arc<Graph>, Arc<Meter>, Arc<LinkWatch>, Subscription) {
        let graph = Graph::new(crate::Seed::from_u64(1), crate::RunMode::Lab);
        let meter = Meter::new();
        graph.owns(&meter, 0, 1);
        let watch = Arc::new(LinkWatch::start(&graph, meter.id).unwrap());
        let subscription = watch.subscribe();
        (graph, meter, watch, subscription)
    }

    fn key(n: usize) -> KeyLine {
        KeyLine {
            label: "CLIENT_TRAFFIC_SECRET_0".into(),
            client_random: (n as u64).to_be_bytes().repeat(4),
            secret: vec![0xab; 32],
        }
    }

    fn capture(meter: &Meter, watch: &LinkWatch) {
        meter.sent(0, &crate::Packet(vec![0x45; 20]));
        watch.pump();
    }

    fn exported_keys(watch: &LinkWatch) -> String {
        let file = watch.pcapng();
        let mut i = 0;
        while i < file.len() {
            let len = le32(&file, i + 4).unwrap() as usize;
            if le32(&file, i).unwrap() == 0x0a {
                assert_eq!(le32(&file, i + 8).unwrap(), 0x544c_534b);
                let key_len = le32(&file, i + 12).unwrap() as usize;
                return String::from_utf8(file[i + 16..i + 16 + key_len].to_vec()).unwrap();
            }
            i += len;
        }
        String::new()
    }

    #[test]
    fn quiet_capture_keeps_keys_after_world_ring_rotates() {
        let (graph, meter, watch, _subscription) = setup();
        graph.key(key(0));
        let original = keylog(&graph);
        capture(&meter, &watch);
        let rows = watch.rows_after(0, 10);

        // Sessions elsewhere rotate the world ring without new packets here.
        for n in 1..=MAX_KEYS {
            graph.key(key(n));
        }
        watch.pump();
        assert_eq!(watch.rows_after(0, 10), rows);
        let current = keylog(&graph);
        assert_eq!(current.lines().count(), MAX_KEYS);
        assert!(!current.contains(&original));
        let exported = exported_keys(&watch);
        assert!(
            exported.starts_with(&original),
            "the retained key is missing"
        );
        assert_eq!(exported, format!("{original}{current}"));

        // Traffic resumes: the watch's bounded cache also evicts the old key.
        capture(&meter, &watch);
        assert_eq!(watch.inner.lock().keys.len(), MAX_KEYS);
        assert_eq!(watch.rows_after(0, 10).len(), 2);
        assert_eq!(exported_keys(&watch), current);
    }

    #[test]
    fn capture_deduplicates_complete_key_lines() {
        let (graph, meter, watch, _subscription) = setup();
        graph.key(key(0));
        capture(&meter, &watch);
        let original = keylog(&graph);
        graph.key(key(0));
        let mut server = key(0);
        server.label = "SERVER_TRAFFIC_SECRET_0".into();
        graph.key(server);
        let mut different = key(0);
        different.secret = vec![0xcd; 32];
        graph.key(different);
        capture(&meter, &watch);
        let world = keylog(&graph);
        assert_eq!(world.lines().count(), 4);
        let exported = exported_keys(&watch);
        assert_eq!(exported, world.strip_prefix(&original).unwrap());
        assert_eq!(exported.lines().count(), 3);
    }

    #[test]
    fn capture_keeps_keys_after_world_is_dropped() {
        let (graph, meter, watch, _subscription) = setup();
        graph.key(key(0));
        let expected = keylog(&graph);
        capture(&meter, &watch);
        drop(graph);
        assert!(watch.graph().is_none());
        assert_eq!(exported_keys(&watch), expected);
    }
}
