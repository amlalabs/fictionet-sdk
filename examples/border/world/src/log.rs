//! The world's log: one JSON object per line, at
//! `/var/lib/fictionet/log.jsonl`. The eval reads it from the world's
//! container.
//!
//! Lines come from `Sites`' events and from the world's own tasks (BGP,
//! the hops). None of them is written on the world's thread: each is
//! handed to a channel that never waits, and a thread writes them out. If
//! the channel is ever full, the line is lost, and the writer says so with
//! a `{"type": "lost", "count": n}` line. The eval throws such a sample away.
//!
//! **Folding.** A port scan or a flood of low-TTL packets would make a line
//! per packet, so the agent could fill the disk and bury its episode. Lines
//! of the kinds that repeat (`blocked`, `ttl_exceeded`, `unreachable`) are
//! folded: the first line of a kind for one sandbox, source and destination
//! in each second is written as it comes, and the rest of that second are
//! counted and written as one more line of the same kind with `"count": n`
//! (and for `blocked`, `"ports": [lowest, highest]`).
//!
//! **No password.** A line never holds the account's password: the writer
//! takes it out of every line, in any case, as `[password]`.

use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fictionet::events::Event as Entry;
use serde_json::{Map, Value, json};

use crate::bank::ACCOUNT;
use crate::events;
use crate::scenario::Scenario;

/// Lines that may wait for the writer.
const QUEUE: usize = 200_000;

/// How long a fold collects repeats before it writes their count.
const FOLD_WINDOW: Duration = Duration::from_secs(1);

/// The most folds open at once. Past this the writer writes them out early.
const MAX_FOLDS: usize = 10_000;

enum Record {
    Entry(Entry),
    Line(Value),
}

/// A handle that sends lines to the log. Cheap to clone.
#[derive(Clone)]
pub struct Log {
    tx: SyncSender<(f64, Record)>,
    lost: Arc<AtomicU64>,
}

fn now() -> f64 {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    ms as f64 / 1000.0
}

impl Log {
    /// Starts the writer thread, which writes every line to `out` and
    /// flushes whenever it has caught up. It ends when every `Log` handle is
    /// gone.
    pub fn start(out: Box<dyn Write + Send>, scenario: Arc<Scenario>) -> Log {
        let (tx, rx) = sync_channel(QUEUE);
        let lost = Arc::new(AtomicU64::new(0));
        let counter = lost.clone();
        std::thread::Builder::new()
            .name("border-log".into())
            .spawn(move || write_all(rx, out, &scenario, &counter))
            .expect("the log thread starts");
        Log { tx, lost }
    }

    fn send(&self, record: Record) {
        if self.tx.try_send((now(), record)).is_err() {
            self.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Logs an event. Called from the event log's callback: it never
    /// waits.
    pub fn entry(&self, entry: &Entry) {
        self.send(Record::Entry(entry.clone()));
    }

    /// Logs a line the world made itself. It must be a JSON object.
    pub fn line(&self, line: Value) {
        self.send(Record::Line(line));
    }
}

/// The kinds of line that are folded.
const FOLDED: [&str; 3] = ["blocked", "ttl_exceeded", "unreachable"];

/// The key lines of one fold share: their kind, sandbox, source and
/// destination, and what they are about. `None` for a line that is never
/// folded.
fn fold_key(line: &Map<String, Value>) -> Option<String> {
    let kind = line.get("type")?.as_str()?;
    if !FOLDED.contains(&kind) {
        return None;
    }
    let sandbox = match line.get("sandbox") {
        Some(Value::Object(s)) => s.get("id").cloned().unwrap_or(Value::Null),
        Some(other) => other.clone(),
        None => Value::Null,
    };
    let field = |name: &str| line.get(name).cloned().unwrap_or(Value::Null);
    Some(json!([kind, sandbox, field("why"), field("protocol"), field("src"), field("dst"), field("hop"), field("from")]).to_string())
}

/// The repeats of one line, counted in the current window.
struct Fold {
    /// The first line, to copy the fields from.
    line: Map<String, Value>,
    count: u64,
    ports: Option<(u64, u64)>,
}

impl Fold {
    fn add(&mut self, line: &Map<String, Value>) {
        self.count += 1;
        if let Some(port) = line.get("dst_port").and_then(Value::as_u64) {
            self.ports = Some(match self.ports {
                Some((lo, hi)) => (lo.min(port), hi.max(port)),
                None => (port, port),
            });
        }
    }

    /// The line that stands for the repeats.
    fn summary(mut self) -> Map<String, Value> {
        self.line.remove("ts");
        self.line.remove("dst_port");
        self.line.insert("count".into(), json!(self.count));
        if let Some((lo, hi)) = self.ports {
            self.line.insert("ports".into(), json!([lo, hi]));
        }
        self.line
    }
}

/// `text` with every copy of the account's password, in any case, replaced.
fn scrub(text: String) -> String {
    let secret = ACCOUNT.password.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();
    if !lower.contains(&secret) {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(i) = lower[at..].find(&secret) {
        out.push_str(&text[at..at + i]);
        out.push_str("[password]");
        at += i + secret.len();
    }
    out.push_str(&text[at..]);
    out
}

struct Writer<'a> {
    out: Box<dyn Write + Send>,
    folds: HashMap<String, Fold>,
    /// When the current fold window began.
    window: Option<Instant>,
    lost: &'a AtomicU64,
    reported: u64,
}

impl Writer<'_> {
    fn write(&mut self, ts: f64, fields: Map<String, Value>) {
        let mut line = Map::new();
        line.insert("ts".into(), json!(ts));
        line.extend(fields);
        let mut text = scrub(Value::Object(line).to_string());
        text.push('\n');
        if let Err(e) = self.out.write_all(text.as_bytes()) {
            eprintln!("border-world: cannot write the log: {e}");
        }
    }

    /// Writes `value`, or counts it in its fold.
    fn line(&mut self, ts: f64, value: Value) {
        let Value::Object(fields) = value else { return };
        let Some(key) = fold_key(&fields) else {
            self.write(ts, fields);
            return;
        };
        if let Some(fold) = self.folds.get_mut(&key) {
            fold.add(&fields);
            return;
        }
        if self.folds.len() >= MAX_FOLDS {
            self.close_folds();
        }
        self.window.get_or_insert_with(Instant::now);
        self.folds.insert(key, Fold { line: fields.clone(), count: 0, ports: None });
        self.write(ts, fields);
    }

    /// Writes the count of every fold that had repeats, and starts a new
    /// window.
    fn close_folds(&mut self) {
        let mut folds: Vec<Fold> = self.folds.drain().map(|(_, f)| f).filter(|f| f.count > 0).collect();
        folds.sort_by(|a, b| {
            let t = |f: &Fold| f.line.get("ts").and_then(Value::as_f64).unwrap_or(0.0);
            t(a).total_cmp(&t(b))
        });
        for fold in folds {
            self.write(now(), fold.summary());
        }
        self.window = None;
    }

    fn report_lost(&mut self) {
        let n = self.lost.load(Ordering::Relaxed);
        if n != self.reported {
            self.reported = n;
            self.write(now(), json!({"type": "lost", "count": n}).as_object().cloned().unwrap_or_default());
        }
    }
}

fn write_all(rx: Receiver<(f64, Record)>, out: Box<dyn Write + Send>, scenario: &Scenario, lost: &AtomicU64) {
    let mut w = Writer { out, folds: HashMap::new(), window: None, lost, reported: 0 };
    let handle = |w: &mut Writer, (ts, record): (f64, Record)| {
        let value = match record {
            Record::Entry(entry) => events::line(scenario, &entry),
            Record::Line(value) => Some(value),
        };
        if let Some(value) = value {
            w.line(ts, value);
        }
        if w.window.is_some_and(|start| start.elapsed() >= FOLD_WINDOW) {
            w.close_folds();
        }
    };
    loop {
        if w.window.is_some_and(|start| start.elapsed() >= FOLD_WINDOW) {
            w.close_folds();
        }
        // Wait without a limit when no fold is open; else until it closes.
        let next = match w.window {
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(start) => rx.recv_timeout(FOLD_WINDOW.saturating_sub(start.elapsed())),
        };
        match next {
            Ok(first) => {
                handle(&mut w, first);
                // Everything already waiting, then one flush.
                while let Ok(more) = rx.try_recv() {
                    handle(&mut w, more);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        w.report_lost();
        let _ = w.out.flush();
    }
    w.close_folds();
    w.report_lost();
    let _ = w.out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_password_never_reaches_a_line() {
        let text = format!("{{\"path\":\"/login/{}\",\"ua\":\"{}\"}}", ACCOUNT.password, ACCOUNT.password.to_uppercase());
        let clean = scrub(text);
        assert_eq!(clean, "{\"path\":\"/login/[password]\",\"ua\":\"[password]\"}");
        assert_eq!(scrub("nothing here".into()), "nothing here");
    }

    #[test]
    fn repeated_lines_fold_into_a_count() {
        let blocked = |port: u16| {
            json!({"type": "blocked", "sandbox": {"id": 1, "name": "a"}, "why": "Refused", "protocol": 6,
                   "src": "10.0.0.2", "dst": "84.21.44.10", "dst_port": port})
        };
        let mut lines = vec![json!({"type": "dns", "name": "x"})];
        lines.extend((1..=1000).map(blocked));
        let mut other = blocked(22);
        other["dst"] = json!("84.21.60.20");
        lines.push(other);
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        struct Out(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for Out {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let lost = AtomicU64::new(0);
        let mut w = Writer { out: Box::new(Out(buf.clone())), folds: HashMap::new(), window: None, lost: &lost, reported: 0 };
        for (i, line) in lines.into_iter().enumerate() {
            w.line(i as f64, line);
        }
        w.close_folds();
        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let got: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(got.len(), 4, "{text}");
        assert_eq!(got[0]["type"], "dns");
        assert_eq!((got[1]["dst_port"].as_u64(), got[1].get("count")), (Some(1), None));
        assert_eq!(got[2]["dst"], "84.21.60.20");
        assert_eq!((got[3]["count"].as_u64(), got[3]["ports"].clone()), (Some(999), json!([2, 1000])));
        assert_eq!(got[3]["dst"], "84.21.44.10");
    }
}
