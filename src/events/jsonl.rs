use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::JoinHandle;

use crate::stdlib::codec::Wire;
use crate::sync::Mutex;

use super::{ConnInfo, Event, Limits, Metadata, Observation, Observer, Stamp};

/// A bounded native JSON Lines exporter.
///
/// The run only enqueues owned events. Serialization and writes happen on a
/// worker thread. A full queue counts loss without waiting. Call [`Self::finish`]
/// outside the run to drain output and report loss or writer errors. Worker
/// scheduling can affect overflow, so use [`super::Memory`] for lab evidence.
pub struct Jsonl {
    sender: Mutex<Option<SyncSender<Event>>>,
    worker: Mutex<Option<JoinHandle<io::Result<()>>>>,
    status: Arc<Status>,
    limits: Limits,
}

#[derive(Default)]
struct Status {
    bytes: AtomicUsize,
    pending: AtomicU64,
    lost: AtomicU64,
    failed: AtomicBool,
}

impl Jsonl {
    /// Creates or truncates a JSONL file and starts its worker.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> io::Result<Self> {
        Self::new(io::BufWriter::new(std::fs::File::create(path)?), limits)
    }

    /// Starts a worker for a writer owned by the integration.
    pub fn new(mut writer: impl Write + Send + 'static, limits: Limits) -> io::Result<Self> {
        let (sender, receiver) = sync_channel::<Event>(limits.events);
        let status = Arc::new(Status::default());
        let worker_status = status.clone();
        let worker = std::thread::Builder::new()
            .name("fictionet-jsonl".into())
            .spawn(move || {
                struct Failure(Arc<Status>, bool);
                impl Drop for Failure {
                    fn drop(&mut self) {
                        if !self.1 {
                            self.0.failed.store(true, Ordering::Release);
                        }
                    }
                }
                let mut guard = Failure(worker_status, false);
                for event in receiver {
                    let bytes = match event.to_json().to_bytes() {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            guard.0.lost.fetch_add(1, Ordering::Relaxed);
                            guard.0.bytes.fetch_sub(event.size(), Ordering::Relaxed);
                            guard.0.pending.fetch_sub(1, Ordering::Relaxed);
                            continue;
                        }
                    };
                    writer.write_all(&bytes)?;
                    writer.write_all(b"\n")?;
                    // Release the queue budget only after a successful flush.
                    writer.flush()?;
                    guard.0.bytes.fetch_sub(event.size(), Ordering::Relaxed);
                    guard.0.pending.fetch_sub(1, Ordering::Relaxed);
                }
                let lost = guard.0.lost.load(Ordering::Relaxed);
                if lost != 0 {
                    writeln!(writer, "{{\"source\":\"events\",\"kind\":\"lost\",\"fields\":{{\"count\":{lost}}}}}")?;
                }
                writer.flush()?;
                guard.1 = true;
                Ok(())
            })?;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            worker: Mutex::new(Some(worker)),
            status,
            limits,
        })
    }

    /// Events rejected by the queue or left unwritten by a failed worker.
    pub fn lost(&self) -> u64 {
        self.status.lost.load(Ordering::Relaxed)
            + if self.status.failed.load(Ordering::Acquire) {
                self.status.pending.load(Ordering::Relaxed)
            } else {
                0
            }
    }

    /// Seals input, drains the worker, and refuses incomplete output.
    /// Call this from host code, never from an observer callback.
    pub fn finish(&self) -> io::Result<()> {
        self.sender.lock().take();
        if let Some(worker) = self.worker.lock().take() {
            worker
                .join()
                .map_err(|_| io::Error::other("JSONL worker panicked"))??;
        }
        if self.status.failed.load(Ordering::Acquire) || self.lost() != 0 {
            return Err(io::Error::other(format!(
                "incomplete JSONL output: {} events lost",
                self.lost()
            )));
        }
        Ok(())
    }
}

impl Observer for Jsonl {
    fn lost(&self, count: u64) {
        self.status.lost.fetch_add(count, Ordering::Relaxed);
    }

    fn enabled(&self, _: Metadata, _: &ConnInfo) -> bool {
        true
    }

    fn observe(&self, stamp: Stamp, observation: Observation<'_>) {
        let Observation::Event(event) = observation;
        let sender = self.sender.lock();
        let Some(sender) = sender.as_ref() else {
            self.status.lost.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let size = event.size();
        if self.status.pending.load(Ordering::Relaxed) >= self.limits.events as u64
            || self.status.failed.load(Ordering::Acquire)
            || self
                .status
                .bytes
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |bytes| {
                    bytes
                        .checked_add(size)
                        .filter(|total| *total <= self.limits.bytes)
                })
                .is_err()
        {
            self.status.lost.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut event = event.clone();
        event.seq = stamp.seq;
        event.at = stamp.at;
        // Event cloning can shrink string capacities.
        self.status
            .bytes
            .fetch_sub(size - event.size(), Ordering::Relaxed);
        let size = event.size();
        self.status.pending.fetch_add(1, Ordering::Relaxed);
        if sender.try_send(event).is_err() {
            self.status.pending.fetch_sub(1, Ordering::Relaxed);
            self.status.bytes.fetch_sub(size, Ordering::Relaxed);
            self.status.lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn end(&self, _: crate::time::Instant) {
        self.sender.lock().take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Instant;
    use std::sync::mpsc::{Receiver, Sender, channel};

    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn deliver(jsonl: &Jsonl, seq: u64) {
        let event = Event::new("shop", "order").field("item", "pump");
        jsonl.observe(
            Stamp {
                seq,
                at: Instant::ZERO,
            },
            Observation::Event(&event),
        );
    }

    #[test]
    fn jsonl_preserves_the_event_line_format() {
        let output = Output::default();
        let jsonl = Jsonl::new(output.clone(), Limits::new(10, 8192)).unwrap();
        deliver(&jsonl, 7);
        jsonl.finish().unwrap();
        let mut expected = Event::new("shop", "order").field("item", "pump");
        expected.seq = 7;
        let mut bytes = expected.to_json().to_bytes().unwrap();
        bytes.push(b'\n');
        assert_eq!(*output.0.lock(), bytes);
        assert_eq!(jsonl.lost(), 0);
    }

    #[test]
    fn serialization_failure_skips_only_that_event() {
        let output = Output::default();
        let jsonl = Jsonl::new(output.clone(), Limits::new(10, 4 << 20)).unwrap();
        // Public fields may be mutated after bounded construction.
        let mut event = Event::new("test", "invalid");
        event.summary = "x".repeat(1 << 20);
        jsonl.observe(
            Stamp {
                seq: 1,
                at: Instant::ZERO,
            },
            Observation::Event(&event),
        );
        deliver(&jsonl, 2);
        assert!(jsonl.finish().is_err());
        assert_eq!(jsonl.lost(), 1);
        let output = output.0.lock();
        let lines: Vec<_> = output
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| crate::stdlib::protocols::json::Value::parse(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].get("seq").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(
            lines[1]
                .get("fields")
                .unwrap()
                .get("count")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    struct Blocked {
        started: Option<Sender<()>>,
        release: Receiver<()>,
        output: Output,
    }
    impl Write for Blocked {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(started) = self.started.take() {
                started.send(()).unwrap();
                self.release.recv().unwrap();
            }
            self.output.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn full_queue_counts_loss_without_waiting_for_writer() {
        let (started, ready) = channel();
        let (release, blocked) = channel();
        let output = Output::default();
        let jsonl = Jsonl::new(
            Blocked {
                started: Some(started),
                release: blocked,
                output: output.clone(),
            },
            Limits::new(2, 8192),
        )
        .unwrap();
        deliver(&jsonl, 1);
        ready.recv().unwrap();
        for seq in 2..=1000 {
            deliver(&jsonl, seq);
        }
        assert_eq!(jsonl.lost(), 998);
        assert_eq!(jsonl.status.pending.load(Ordering::Relaxed), 2);
        assert!(jsonl.status.bytes.load(Ordering::Relaxed) <= 8192);
        release.send(()).unwrap();
        assert!(jsonl.finish().is_err());
        let output = output.0.lock();
        let lines: Vec<_> = output
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(lines.len(), 3);
        let lost = crate::stdlib::protocols::json::Value::parse(lines[2]).unwrap();
        assert_eq!(lost.get("kind").and_then(|v| v.as_str()), Some("lost"));
        assert_eq!(
            lost.get("fields")
                .unwrap()
                .get("count")
                .and_then(|v| v.as_u64()),
            Some(998)
        );
    }

    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("writer failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_errors_make_finish_fail() {
        let jsonl = Jsonl::new(Broken, Limits::new(10, 8192)).unwrap();
        deliver(&jsonl, 1);
        assert!(jsonl.finish().is_err());
        assert_eq!(jsonl.lost(), 1);
        assert!(jsonl.finish().is_err());
    }

    #[test]
    fn byte_budget_rejects_before_queueing() {
        let jsonl = Jsonl::new(Output::default(), Limits::new(10, 1)).unwrap();
        deliver(&jsonl, 1);
        assert_eq!(jsonl.lost(), 1);
        assert_eq!(jsonl.status.bytes.load(Ordering::Relaxed), 0);
        assert!(jsonl.finish().is_err());
    }
}
