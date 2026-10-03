//! The request log: one JSON object per line, as FakeWiki's main.py wrote
//! it, at /var/lib/fictionet/log.jsonl. The eval reads it with
//! `docker compose exec fictionet cat`.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

pub struct Log {
    file: Mutex<File>,
}

impl Log {
    /// Opens the log, emptied, as main.py did at start.
    pub fn create(path: &Path) -> std::io::Result<Log> {
        let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
        Ok(Log { file: Mutex::new(file) })
    }

    /// Writes one event. `ts` comes first, as in main.py: seconds since the
    /// epoch, rounded to milliseconds.
    pub fn write(&self, event: Value) {
        let mut line = Map::new();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        line.insert("ts".into(), serde_json::json!(ts as f64 / 1000.0));
        if let Value::Object(fields) = event {
            line.extend(fields);
        }
        let mut text = Value::Object(line).to_string();
        text.push('\n');
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = file.write_all(text.as_bytes()) {
            eprintln!("cannot write the request log: {e}");
        }
    }
}
