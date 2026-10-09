//! JSON Lines output for example worlds, using the run's event writer.

use fictionet::{Cx, events::Event, sync::Mutex};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FOLD_WINDOW: Duration = Duration::from_secs(1);
const MAX_FOLDS: usize = 10_000;

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
    cx: OnceLock<Cx>,
    transform: fn(String) -> String,
    writer: Mutex<Option<Writer>>,
}
impl Log {
    pub fn new(
        out: Box<dyn Write + Send>,
        folded: &'static [&'static str],
        transform: fn(String) -> String,
    ) -> Self {
        Self(Arc::new(Inner {
            cx: OnceLock::new(),
            transform,
            writer: Mutex::new(Some(Writer::new(out, folded, transform))),
        }))
    }
    pub fn attach(&self, fcx: &Cx) {
        if let Some(writer) = self.0.writer.lock().take() {
            self.0
                .cx
                .set(fcx.clone())
                .unwrap_or_else(|_| panic!("log already attached"));
            let folds = !writer.folded.is_empty();
            fcx.events().to_writer(Box::new(writer));
            if folds {
                fcx.spawn(|fcx| async move {
                    while fcx.sleep(FOLD_WINDOW).await.is_ok() {
                        fcx.record(Event::new("example", "flush"));
                    }
                    Ok(())
                });
            }
        }
    }
    pub fn write(&self, value: Value) {
        let mut line = Map::new();
        line.insert("ts".into(), json!(now()));
        if let Value::Object(fields) = value {
            line.extend(fields);
        }
        self.0.cx.get().expect("log attached to a run").record(
            Event::new("example", "line")
                .field("line", (self.0.transform)(Value::Object(line).to_string())),
        );
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

pub struct Writer {
    out: Box<dyn Write + Send>,
    folds: HashMap<String, Fold>,
    window: Option<Instant>,
    folded: &'static [&'static str],
    transform: fn(String) -> String,
    pending: Vec<u8>,
    failed: bool,
}
impl Writer {
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
            pending: Vec::new(),
            failed: false,
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

    /// Writes the count of every fold that had repeats, and starts a new
    /// window.
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
}
impl Write for Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let result = (|| {
            self.pending.extend_from_slice(bytes);
            while let Some(end) = self.pending.iter().position(|&b| b == b'\n') {
                let entry: Value = serde_json::from_slice(&self.pending[..end])?;
                self.pending.drain(..=end);
                if entry["source"] == "example" && entry["kind"] == "line" {
                    if let Some(text) = entry["fields"]["line"].as_str() {
                        let line: Value = serde_json::from_str(text)?;
                        self.line(line["ts"].as_f64().unwrap_or(0.0), line)?;
                    }
                } else if entry["source"] == "events" && entry["kind"] == "lost" {
                    self.line(
                        now(),
                        json!({"type": "lost", "count": entry["fields"]["count"]}),
                    )?;
                }
                if self
                    .window
                    .is_some_and(|start| start.elapsed() >= FOLD_WINDOW)
                {
                    self.close_folds()?;
                }
            }
            Ok(bytes.len())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
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

    #[test]
    fn event_writer_preserves_lines_and_reports_loss() {
        let output = Output(Arc::new(Mutex::new(Vec::new())));
        let mut writer = Writer::new(Box::new(output.clone()), &[], |s| s);
        writer
            .write_all(b"{\"source\":\"tcp\",\"kind\":\"sent\"}\n")
            .unwrap();
        let line = json!({"ts": 123.5, "type": "http", "path": "/page"});
        let event =
            json!({"source": "example", "kind": "line", "fields": {"line": line.to_string()}});
        let encoded = format!("{event}\n");
        writer.write_all(&encoded.as_bytes()[..7]).unwrap();
        writer.write_all(&encoded.as_bytes()[7..]).unwrap();
        writer
            .write_all(b"{\"source\":\"events\",\"kind\":\"lost\",\"fields\":{\"count\":7}}\n")
            .unwrap();
        writer.flush().unwrap();
        let bytes = output.0.lock();
        let lines: Vec<Value> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], line);
        assert_eq!(lines[1]["type"], "lost");
        assert_eq!(lines[1]["count"], 7);
    }
}
