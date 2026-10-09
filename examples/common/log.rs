//! JSON Lines output for example worlds, with a separate queue for log lines.
//!
//! Only example lines enter the bounded writer queue, so packet events cannot
//! crowd them out. Real runs write on a thread; labs write synchronously.
//! The writer's timeout closes fold windows when no new line arrives. It uses
//! wall time without spawning a run task or recording transport events, so it
//! cannot keep a lab alive or add lines to observations and golden transcripts.
//! Closing the run drains the queue and closes the remaining folds.

use fictionet::{Cx, sync::Mutex};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FOLD_WINDOW: Duration = Duration::from_secs(1);
const MAX_FOLDS: usize = 10_000;
const QUEUE: usize = 200_000;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0) as f64
        / 1000.0
}

/// A log attached to a run before its first line is written.
#[derive(Clone)]
pub struct Log(Arc<Inner>);
struct Inner {
    backend: Mutex<Backend>,
    lost: Arc<AtomicU64>,
}
enum Backend {
    Pending(Writer),
    Lab(Writer),
    Real(SyncSender<Value>, std::thread::JoinHandle<()>),
    Closed,
}
struct Finish(Arc<Inner>);
impl Drop for Finish {
    fn drop(&mut self) {
        let backend = std::mem::replace(&mut *self.0.backend.lock(), Backend::Closed);
        if let Backend::Real(sender, thread) = backend {
            drop(sender);
            thread.join().expect("the log writer finishes");
        }
    }
}
impl Log {
    /// Prepares a JSON Lines output with folding and text transformation.
    pub fn new(
        out: Box<dyn Write + Send>,
        folded: &'static [&'static str],
        transform: fn(String) -> String,
    ) -> Self {
        Self(Arc::new(Inner {
            backend: Mutex::new(Backend::Pending(Writer::new(out, folded, transform))),
            lost: Arc::new(AtomicU64::new(0)),
        }))
    }
    /// Starts delivery and arranges for the run's end to drain the output.
    pub fn attach(&self, fcx: &Cx) {
        let mut backend = self.0.backend.lock();
        let Backend::Pending(writer) = std::mem::replace(&mut *backend, Backend::Closed) else {
            panic!("log already attached");
        };
        *backend = if fcx.mode() == fictionet::RunMode::Lab {
            Backend::Lab(writer)
        } else {
            let (sender, receiver) = mpsc::sync_channel(QUEUE);
            let lost = self.0.lost.clone();
            let thread = std::thread::Builder::new()
                .name("example-log".into())
                .spawn(move || {
                    if let Err(error) = write_all(receiver, writer, &lost) {
                        eprintln!("cannot write the example log: {error}");
                    }
                })
                .expect("the log writer starts");
            Backend::Real(sender, thread)
        };
        drop(backend);
        let finish = Finish(self.0.clone());
        fcx.events().subscribe(move |_| {
            let _ = &finish;
        });
    }
    /// Delivers a JSON object with its timestamp to the output.
    pub fn write(&self, value: Value) {
        let mut line = Map::new();
        line.insert("ts".into(), json!(now()));
        if let Value::Object(fields) = value {
            line.extend(fields);
        }
        let value = Value::Object(line);
        match &mut *self.0.backend.lock() {
            Backend::Lab(writer) => {
                if let Err(error) = writer.line(now(), value).and_then(|()| writer.flush()) {
                    writer.failed = true;
                    eprintln!("cannot write the example log: {error}");
                }
            }
            Backend::Real(sender, _) => {
                if sender.try_send(value).is_err() {
                    self.0.lost.fetch_add(1, Ordering::Relaxed);
                }
            }
            Backend::Pending(_) => panic!("log attached to a run"),
            Backend::Closed => {}
        }
    }
}

fn write_all(
    receiver: mpsc::Receiver<Value>,
    mut writer: Writer,
    lost: &AtomicU64,
) -> std::io::Result<()> {
    let mut reported = 0;
    loop {
        let next = match writer.window {
            Some(start) => receiver.recv_timeout(FOLD_WINDOW.saturating_sub(start.elapsed())),
            None => receiver.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        let done = match next {
            Ok(line) => {
                writer.line(line["ts"].as_f64().unwrap_or(0.0), line)?;
                false
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => true,
        };
        if done
            || writer
                .window
                .is_some_and(|start| start.elapsed() >= FOLD_WINDOW)
        {
            writer.close_folds()?;
        }
        let count = lost.load(Ordering::Relaxed);
        if count != reported {
            writer.line(now(), json!({"type": "lost", "count": count}))?;
            reported = count;
        }
        writer.flush()?;
        if done {
            return Ok(());
        }
    }
}

/// The key lines of one fold share: their kind, sandbox, source and
/// destination, and what they are about. `None` for a line that is never
/// folded.
pub fn fold_key(line: &Map<String, Value>, folded: &[&str]) -> Option<String> {
    let kind = line.get("type")?.as_str()?;
    // A line with a count is a fold already: the network's own.
    if !folded.contains(&kind) || line.contains_key("count") {
        return None;
    }
    let sandbox = match line.get("sandbox") {
        Some(Value::Object(s)) => s.get("id").cloned().unwrap_or(Value::Null),
        Some(other) => other.clone(),
        None => Value::Null,
    };
    let field = |name: &str| line.get(name).cloned().unwrap_or(Value::Null);
    Some(
        json!([
            kind,
            sandbox,
            field("why"),
            field("protocol"),
            field("src"),
            field("dst"),
            field("hop"),
            field("from")
        ])
        .to_string(),
    )
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

/// Writes JSON objects and summaries of repeated lines.
pub struct Writer {
    out: Box<dyn Write + Send>,
    folds: HashMap<String, Fold>,
    window: Option<Instant>,
    folded: &'static [&'static str],
    transform: fn(String) -> String,
    failed: bool,
}
impl Writer {
    /// Prepares an output with the given fold kinds and text transformation.
    pub fn new(
        out: Box<dyn Write + Send>,
        folded: &'static [&'static str],
        transform: fn(String) -> String,
    ) -> Self {
        Self {
            out,
            folds: HashMap::new(),
            window: None,
            folded,
            transform,
            failed: false,
        }
    }
    fn write_line(&mut self, ts: f64, fields: Map<String, Value>) -> std::io::Result<()> {
        let mut line = Map::new();
        line.insert("ts".into(), json!(ts));
        line.extend(fields);
        let mut text = (self.transform)(Value::Object(line).to_string());
        text.push('\n');
        let result = self.out.write_all(text.as_bytes());
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Writes `value`, or counts it in its fold.
    pub fn line(&mut self, ts: f64, value: Value) -> std::io::Result<()> {
        let Value::Object(fields) = value else {
            return Ok(());
        };
        let Some(key) = fold_key(&fields, self.folded) else {
            self.write_line(ts, fields)?;
            return Ok(());
        };
        if let Some(fold) = self.folds.get_mut(&key) {
            fold.add(&fields);
            return Ok(());
        }
        if self.folds.len() >= MAX_FOLDS {
            self.close_folds()?;
        }
        self.window.get_or_insert_with(Instant::now);
        self.folds.insert(
            key,
            Fold {
                line: fields.clone(),
                count: 0,
                ports: None,
            },
        );
        self.write_line(ts, fields)?;
        Ok(())
    }

    /// Writes repeat counts and starts a new fold window.
    pub fn close_folds(&mut self) -> std::io::Result<()> {
        let mut folds: Vec<Fold> = self
            .folds
            .drain()
            .map(|(_, f)| f)
            .filter(|f| f.count > 0)
            .collect();
        folds.sort_by(|a, b| {
            let t = |f: &Fold| f.line.get("ts").and_then(Value::as_f64).unwrap_or(0.0);
            t(a).total_cmp(&t(b))
        });
        for fold in folds {
            self.write_line(now(), fold.summary())?;
        }
        self.window = None;
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let result = self.out.flush();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        if !self.failed {
            let _ = self.close_folds().and_then(|()| self.out.flush());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn lines(output: &Output) -> Vec<Value> {
        String::from_utf8(output.0.lock().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn writer_preserves_lines_and_reports_loss() {
        let output = Output(Arc::new(Mutex::new(Vec::new())));
        let writer = Writer::new(Box::new(output.clone()), &[], |s| s);
        let (sender, receiver) = mpsc::sync_channel(1);
        let line = json!({"ts": 123.5, "type": "http", "path": "/page"});
        sender.try_send(line.clone()).unwrap();
        let lost = AtomicU64::new(0);
        for _ in 0..7 {
            assert!(sender.try_send(line.clone()).is_err());
            lost.fetch_add(1, Ordering::Relaxed);
        }
        drop(sender);
        write_all(receiver, writer, &lost).unwrap();
        let lines = lines(&output);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], line);
        assert_eq!(lines[1]["type"], "lost");
        assert_eq!(lines[1]["count"], 7);
    }

    struct PausedOutput {
        output: Output,
        entered: Option<mpsc::Sender<()>>,
        release: mpsc::Receiver<()>,
    }
    impl Write for PausedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(30)).unwrap();
            }
            self.output.write(bytes)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.output.flush()
        }
    }

    #[test]
    fn real_port_scan_keeps_every_example_line() {
        let output = Output(Arc::new(Mutex::new(Vec::new())));
        let (entered, waiting) = mpsc::channel();
        let (release, paused) = mpsc::channel();
        let out = PausedOutput {
            output: output.clone(),
            entered: Some(entered),
            release: paused,
        };
        let result = fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                let log = Log::new(Box::new(out), &["blocked"], |s| s);
                log.attach(&fcx);
                log.write(json!({"type": "blocked", "dst_port": 1}));
                waiting.recv_timeout(Duration::from_secs(5)).unwrap();
                for port in 2..=65_535u32 {
                    // Packet capture and TCP bookkeeping surround each blocked-port event.
                    for kind in ["received", "sent", "decoded", "closed"] {
                        fcx.record(fictionet::events::Event::new("tcp", kind).field("port", port));
                    }
                    log.write(json!({"type": "blocked", "dst_port": port}));
                }
                release.send(()).unwrap();
                Err(std::io::Error::other("scan complete").into())
            },
        ));
        assert!(result.is_err());
        let lines = lines(&output);
        assert!(lines.iter().all(|line| line["type"] == "blocked"));
        let count: u64 = lines
            .iter()
            .map(|line| line["count"].as_u64().unwrap_or(1))
            .sum();
        assert_eq!(count, 65_535);
        assert!(
            lines
                .iter()
                .any(|line| line["count"].as_u64().is_some_and(|n| n > 1))
        );
    }

    #[test]
    fn idle_writer_closes_the_fold_window() {
        struct Lines(mpsc::Sender<Vec<u8>>);
        impl Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.send(bytes.to_vec()).unwrap();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (sent, received) = mpsc::channel();
        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                let log = Log::new(Box::new(Lines(sent)), &["blocked"], |s| s);
                log.attach(&fcx);
                log.write(json!({"type": "blocked", "dst_port": 1}));
                log.write(json!({"type": "blocked", "dst_port": 2}));
                let first: Value =
                    serde_json::from_slice(&received.recv_timeout(Duration::from_secs(5)).unwrap())
                        .unwrap();
                let summary: Value =
                    serde_json::from_slice(&received.recv_timeout(Duration::from_secs(5)).unwrap())
                        .unwrap();
                assert_eq!(first["dst_port"], 1);
                assert_eq!(summary["count"], 1);
                assert!(
                    fcx.events()
                        .all()
                        .iter()
                        .all(|event| event.source != "example")
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn lab_ends_and_transport_stays_out_of_events() {
        let output = Output(Arc::new(Mutex::new(Vec::new())));
        let out = output.clone();
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                let log = Log::new(Box::new(out), &["blocked"], |s| s);
                log.attach(&fcx);
                log.write(json!({"type": "blocked", "dst_port": 1}));
                log.write(json!({"type": "blocked", "dst_port": 2}));
                assert!(
                    fcx.events()
                        .all()
                        .iter()
                        .all(|event| event.source != "example")
                );
                Ok(())
            },
        ))
        .unwrap();
        let lines = lines(&output);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["count"], 1);
    }
}
