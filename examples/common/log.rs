//! JSON Lines output for example worlds, with a separate queue for log lines.
//!
//! Only example lines enter the bounded writer queue, so packet events cannot
//! crowd them out. Real runs write on a thread; labs write synchronously.
//! The writer's timeout closes fold windows when no new line arrives. It uses
//! wall time without spawning a run task or recording transport events, so it
//! cannot keep a lab alive or add lines to observations and golden transcripts.
//! Closing the run drains the queue and closes the remaining folds. Finalization
//! checks output failures and lost lines before acknowledging the harness.

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
    failure: Arc<Mutex<Option<String>>>,
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
        let _ = Log(self.0.clone()).finish();
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
            failure: Arc::new(Mutex::new(None)),
        }))
    }
    /// Latches a world-level failure unless a failure has already been recorded.
    /// [`Self::health`], [`Finalization::wait`] and [`Finalization::acknowledge`]
    /// report it, so a failed world cannot acknowledge successful finalization.
    pub fn fail(&self, reason: impl Into<String>) {
        self.0.failure.lock().get_or_insert_with(|| reason.into());
    }

    /// Reports world or output failure or lost lines, including final flush failures.
    pub fn health(&self) -> std::io::Result<()> {
        if let Some(error) = &*self.0.failure.lock() {
            return Err(std::io::Error::other(error.clone()));
        }
        if self.0.lost.load(Ordering::Relaxed) != 0 {
            return Err(std::io::Error::other("the world lost log lines"));
        }
        Ok(())
    }

    /// Drains the output after all producers have stopped and checks its health.
    pub fn finish(&self) -> std::io::Result<()> {
        let backend = std::mem::replace(&mut *self.0.backend.lock(), Backend::Closed);
        match backend {
            Backend::Real(sender, thread) => {
                drop(sender);
                if thread.join().is_err() {
                    *self.0.failure.lock() = Some("the log writer panicked".into());
                }
            }
            Backend::Lab(mut writer) | Backend::Pending(mut writer) => {
                if let Err(error) = writer.close_folds().and_then(|()| writer.flush()) {
                    *self.0.failure.lock() = Some(error.to_string());
                }
            }
            Backend::Closed => {}
        }
        self.health()
    }

    /// Prepares the private request and acknowledgement files for this run.
    pub fn finalization(&self, directory: &std::path::Path) -> std::io::Result<Finalization> {
        let request = directory.join("finalize");
        let acknowledgement = directory.join("finalized");
        for path in [&request, &acknowledgement] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Finalization {
            log: self.clone(),
            request,
            acknowledgement,
        })
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
            let failure = self.0.failure.clone();
            let thread = std::thread::Builder::new()
                .name("example-log".into())
                .spawn(move || {
                    if let Err(error) = write_all(receiver, writer, &lost) {
                        *failure.lock() = Some(error.to_string());
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
                    *self.0.failure.lock() = Some(error.to_string());
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

/// The trusted harness requests shutdown through files in the world's private directory.
pub struct Finalization {
    log: Log,
    request: std::path::PathBuf,
    acknowledgement: std::path::PathBuf,
}
impl Finalization {
    /// Stops the run on a request, or fails it if the world or logging failed.
    pub async fn wait(&self, fcx: &Cx) -> fictionet::Result {
        loop {
            self.log.health()?;
            if self.request.try_exists()? {
                fcx.cancel();
                return Ok(());
            }
            fcx.sleep(Duration::from_millis(50)).await?;
        }
    }

    /// Acknowledges only after the run ended and its output drained successfully.
    pub fn acknowledge(&self, result: fictionet::Result) -> fictionet::Result {
        result?;
        self.log.finish()?;
        if !self.request.try_exists()? {
            return Err(std::io::Error::other("world ended without finalization").into());
        }
        let temporary = self.acknowledgement.with_extension("tmp");
        std::fs::write(&temporary, b"ok\n")?;
        std::fs::rename(temporary, &self.acknowledgement)?;
        Ok(())
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
        }
    }
    fn write_line(&mut self, ts: f64, fields: Map<String, Value>) -> std::io::Result<()> {
        let mut line = Map::new();
        line.insert("ts".into(), json!(ts));
        line.extend(fields);
        let mut text = (self.transform)(Value::Object(line).to_string());
        text.push('\n');
        self.out.write_all(text.as_bytes())
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
        self.out.flush()
    }
}

/// Checks repeated-line folding with the supplied world configuration. The
/// worlds' own tests call it with their folded types and line transforms.
pub fn assert_repeated_lines_fold(
    folded: &'static [&'static str],
    transform: fn(String) -> String,
) {
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
    let mut w = Writer::new(Box::new(Out(buf.clone())), folded, transform);
    for (i, line) in lines.into_iter().enumerate() {
        w.line(i as f64, line).unwrap();
    }
    w.close_folds().unwrap();
    let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    let got: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(got.len(), 4, "{text}");
    assert_eq!(got[0]["type"], "dns");
    assert_eq!(
        (got[1]["dst_port"].as_u64(), got[1].get("count")),
        (Some(1), None)
    );
    assert_eq!(got[2]["dst"], "84.21.60.20");
    assert_eq!(
        (got[3]["count"].as_u64(), got[3]["ports"].clone()),
        (Some(999), json!([2, 1000]))
    );
    assert_eq!(got[3]["dst"], "84.21.44.10");
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingOutput {
        writes: usize,
        flush_fails: bool,
    }
    impl Write for FailingOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            if self.writes > 1 && !self.flush_fails {
                return Err(std::io::Error::other("intentional write failure"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.flush_fails {
                Err(std::io::Error::other("intentional flush failure"))
            } else {
                Ok(())
            }
        }
    }

    fn failing_log(flush_fails: bool) -> Log {
        Log::new(
            Box::new(FailingOutput {
                writes: 0,
                flush_fails,
            }),
            &[],
            |s| s,
        )
    }

    #[test]
    fn real_write_failure_survives_run_teardown() {
        let log = failing_log(false);
        let output = log.clone();
        fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                output.attach(&fcx);
                output.write(json!({"type": "first"}));
                output.write(json!({"type": "second"}));
                Ok(())
            },
        ))
        .unwrap();
        assert!(
            log.finish()
                .unwrap_err()
                .to_string()
                .contains("write failure")
        );
        assert!(log.health().is_err());
    }

    #[test]
    fn writer_failure_stops_the_serving_run_without_acknowledgement() {
        let log = failing_log(false);
        let dir = std::env::temp_dir().join(format!("fictionet-failed-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let finalization = Arc::new(log.finalization(&dir).unwrap());
        let shutdown = finalization.clone();
        let result = fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                log.attach(&fcx);
                log.write(json!({"type": "first"}));
                log.write(json!({"type": "second"}));
                shutdown.wait(&fcx).await
            },
        ));
        assert!(result.is_err());
        assert!(finalization.acknowledge(result).is_err());
        assert!(!finalization.acknowledgement.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn world_failure_stops_the_serving_run_without_acknowledgement() {
        let log = Log::new(Box::new(std::io::sink()), &[], |s| s);
        let dir =
            std::env::temp_dir().join(format!("fictionet-failed-world-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let finalization = Arc::new(log.finalization(&dir).unwrap());
        let shutdown = finalization.clone();
        std::fs::write(&finalization.request, b"").unwrap();
        let result = fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                log.attach(&fcx);
                log.fail("cannot record the address");
                log.fail("later failure");
                assert_eq!(
                    log.health().unwrap_err().to_string(),
                    "cannot record the address"
                );
                shutdown.wait(&fcx).await
            },
        ));
        assert!(
            result
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("cannot record the address")
        );
        assert!(finalization.acknowledge(result).is_err());
        assert!(finalization.acknowledge(Ok(())).is_err());
        assert!(!finalization.acknowledgement.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn lab_flush_failure_survives_run_teardown() {
        let log = failing_log(true);
        let output = log.clone();
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                output.attach(&fcx);
                output.write(json!({"type": "first"}));
                Ok(())
            },
        ))
        .unwrap();
        assert!(
            log.finish()
                .unwrap_err()
                .to_string()
                .contains("flush failure")
        );
    }

    #[test]
    fn acknowledgement_follows_cancellation_and_fold_drain() {
        let dir = std::env::temp_dir().join(format!("fictionet-finalize-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let output = Output(Arc::new(Mutex::new(Vec::new())));
        let log = Log::new(Box::new(output.clone()), &["blocked"], |s| s);
        let finalization = Arc::new(log.finalization(&dir).unwrap());
        let shutdown = finalization.clone();
        std::fs::write(&finalization.request, b"").unwrap();
        let result = fictionet::block_on(fictionet::run(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                log.attach(&fcx);
                log.write(json!({"type": "blocked"}));
                fcx.spawn(move |task| async move {
                    task.cancelled().await;
                    log.write(json!({"type": "blocked"}));
                    Ok(())
                });
                shutdown.wait(&fcx).await
            },
        ));
        assert!(!finalization.acknowledgement.exists());
        finalization.acknowledge(result).unwrap();
        assert_eq!(lines(&output).len(), 2);
        assert_eq!(lines(&output)[1]["count"], 1);
        assert_eq!(
            std::fs::read_to_string(&finalization.acknowledgement).unwrap(),
            "ok\n"
        );
        let failed = failing_log(true);
        let finalization = failed.finalization(&dir).unwrap();
        std::fs::write(&finalization.request, b"").unwrap();
        assert!(finalization.acknowledge(Ok(())).is_err());
        assert!(!finalization.acknowledgement.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct SlowWriter {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Write for SlowWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn recording_returns_while_the_writer_is_blocked() {
        let (entered, writing) = mpsc::channel();
        let (release, waiting) = mpsc::channel();
        let (recorded, returned) = mpsc::channel();
        let callback = std::thread::spawn(move || {
            fictionet::block_on(fictionet::run(
                fictionet::Seed::from_u64(1),
                move |fcx| async move {
                    let log = Log::new(
                        Box::new(SlowWriter {
                            entered,
                            release: waiting,
                        }),
                        &[],
                        |s| s,
                    );
                    log.attach(&fcx);
                    log.write(serde_json::json!({"type": "http"}));
                    recorded.send(()).unwrap();
                    Ok(())
                },
            ))
            .unwrap();
        });
        writing.recv_timeout(Duration::from_secs(2)).unwrap();
        let completed = returned.recv_timeout(Duration::from_secs(2));
        release.send(()).unwrap();
        callback.join().unwrap();
        completed.expect("recording returns before the disk write finishes");
    }

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
