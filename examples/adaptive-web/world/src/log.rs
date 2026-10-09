//! The request log: one JSON object per line, at
//! /var/lib/fictionet/log.jsonl. The eval reads it with
//! `docker compose exec fictionet cat`.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

pub struct Log {
    sender: Option<Sender<Vec<u8>>>,
    writer: Option<JoinHandle<()>>,
}

impl Log {
    /// Opens the log, emptied.
    pub fn create(path: &Path) -> std::io::Result<Log> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Self::to_writer(file)
    }

    fn to_writer(mut file: impl Write + Send + 'static) -> std::io::Result<Log> {
        let (sender, receiver) = mpsc::channel::<Vec<u8>>();
        let writer = std::thread::Builder::new()
            .name("request-log".into())
            .spawn(move || {
                for line in receiver {
                    if let Err(e) = file.write_all(&line) {
                        eprintln!("cannot write the request log: {e}");
                        break;
                    }
                }
            })?;
        Ok(Log {
            sender: Some(sender),
            writer: Some(writer),
        })
    }

    /// Queues one event for the writer thread. `ts` comes first: seconds since the epoch, rounded
    /// to milliseconds.
    pub fn write(&self, event: Value) {
        let mut line = Map::new();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        line.insert("ts".into(), serde_json::json!(ts as f64 / 1000.0));
        if let Value::Object(fields) = event {
            line.extend(fields);
        }
        let mut text = Value::Object(line).to_string();
        text.push('\n');
        let _ = self
            .sender
            .as_ref()
            .expect("log is open")
            .send(text.into_bytes());
    }
}

impl Drop for Log {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct SlowWriter {
        entered: Sender<()>,
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
        let log = Log::to_writer(SlowWriter {
            entered,
            release: waiting,
        })
        .unwrap();
        let (recorded, returned) = mpsc::channel();
        let callback = std::thread::spawn(move || {
            log.write(serde_json::json!({"type": "http"}));
            recorded.send(()).unwrap();
            log
        });
        writing.recv_timeout(Duration::from_secs(2)).unwrap();
        let completed = returned.recv_timeout(Duration::from_secs(2));
        release.send(()).unwrap();
        drop(callback.join().unwrap());
        completed.expect("recording returns before the disk write finishes");
    }
}
