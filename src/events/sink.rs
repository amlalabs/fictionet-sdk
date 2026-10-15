#![deny(clippy::let_underscore_must_use)]

use fictionet::sync::Mutex;
use std::io::Write;
#[cfg(feature = "std")]
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::sync::mpsc::{Receiver, sync_channel};

use crate::stdlib::codec::Wire;

use super::{Event, EventLog};
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use super::{MAX_EVENT_BYTES, Store};

/// How many events may wait for a file's writer thread.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
const FILE_QUEUE: usize = 100_000;
/// How many retained event bytes may wait for a file's writer thread.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub(super) const FILE_QUEUE_BYTES: usize = MAX_EVENT_BYTES;

/// A native writer and the events it has not taken from its channel.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub(super) struct Writer {
    thread: std::thread::JoinHandle<()>,
    pending: Arc<AtomicU64>,
}

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
impl Writer {
    pub(super) fn join(self, store: &Store) {
        if self.thread.join().is_err() {
            store.writer_failed.store(true, Ordering::Relaxed);
            // The unwind guard counts the batch; the channel's remainder
            // is still pending. An active drainer may have one send in
            // flight, which can also count itself lost when it fails.
            store
                .lost
                .fetch_add(self.pending.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
}

impl EventLog {
    /// Calls `f` with every event the log holds now, oldest first (with
    /// an `events.dropped` event wherever some were dropped), then with
    /// every event recorded from now on until the run is over, including
    /// events too large to retain. Replay and live events share one FIFO:
    /// `f` runs in sequence order, one call at a time, outside the log and
    /// delivery locks. Once the run is over, `f` gets only what the log holds.
    ///
    /// `f` may read, record, or subscribe to the same log. Reentrant or
    /// concurrent recording queues events for the caller already draining
    /// this subscription. Recording or subscribing may return before those
    /// callbacks finish. Callbacks can run in a different task or thread from
    /// the recorder; no helper thread is created for them. Different
    /// subscriptions may run concurrently. A callback panic propagates to the
    /// caller draining it. If the run ends while a callback is active, that
    /// caller still drains the events already queued for the subscription.
    ///
    /// `f` must return quickly and never block: hand the event to a channel
    /// that never waits.
    pub fn subscribe(&self, f: impl Fn(&Event) + Send + Sync + 'static) {
        self.subscribe_arc(Arc::new(move |event| f(event)));
    }

    /// Writes every event to `path` as JSON Lines ([`Event::to_json`]),
    /// with the same delivery policy as [`EventLog::to_writer`]: what the
    /// log holds now, then each event as it is recorded. The file is created,
    /// or emptied.
    #[cfg(feature = "std")]
    pub fn to_file(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let file = std::fs::File::create(path)?;
        self.to_writer(Box::new(std::io::BufWriter::new(file)));
        Ok(())
    }

    /// Writes every event to `out` as JSON Lines. A native real run with
    /// `std` uses a thread that flushes whenever it has caught up. The run's
    /// end waits for the thread to write and flush every line. In browsers,
    /// labs and builds without `std`, each line is written and flushed
    /// synchronously in the subscription's drainer, without a writer thread.
    /// Replay and live lines follow sequence order, with the callback context
    /// described by [`EventLog::subscribe`]. Successful synchronous sinks lose
    /// no lines.
    ///
    /// A line is lost, and counted ([`EventLog::lost`]), when it does not
    /// fit in the thread's queue (100,000 events or 16 MiB of retained
    /// event data), or when `out` fails. After a queue overflow the file gets
    /// an `events.lost` line with the count so far. After a failed write or
    /// flush the thread writes nothing more, and counts every line after
    /// it, and each line written since the last flush that worked, as
    /// lost. A panic in the native writer is counted the same way and
    /// latched; it is not rethrown at shutdown or after replay. That writer
    /// writes nothing more, including an `events.lost` line. Its queued
    /// events are counted when the thread is joined. A send racing with
    /// finalization can be counted twice, at most one per writer. A native
    /// writer failure makes `lost()` at least one, even if no lines were
    /// pending. Synchronous sink panics still propagate to the drainer's
    /// caller, as in [`EventLog::subscribe`]. A grader throws away a sample
    /// with any line lost.
    pub fn to_writer(&self, out: Box<dyn Write + Send>) {
        if cfg!(target_arch = "wasm32")
            || !cfg!(feature = "std")
            || self.store.mode == crate::RunMode::Lab
        {
            let writer = Mutex::new(Some(out));
            let lost = self.store.lost.clone();
            self.subscribe(move |event| {
                let mut writer = writer.lock();
                let failed = match writer.as_mut() {
                    Some(out) => event.to_json().to_bytes().ok().is_none_or(|mut line| {
                        line.push(b'\n');
                        out.write_all(&line).and_then(|()| out.flush()).is_err()
                    }),
                    None => true,
                };
                if failed {
                    *writer = None;
                    lost.fetch_add(1, Ordering::Relaxed);
                }
            });
            #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
            return;
        }

        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        {
            let (tx, rx) = sync_channel::<Arc<Event>>(FILE_QUEUE);
            let queued = Arc::new(AtomicUsize::new(0));
            let pending = Arc::new(AtomicU64::new(0));
            let lost = self.store.lost.clone();
            let thread = {
                let (lost, queued, pending) = (lost.clone(), queued.clone(), pending.clone());
                let failure = self.store.writer_failed.clone();
                std::thread::Builder::new()
                    .name("fictionet-events".into())
                    .spawn(move || write_lines(rx, out, &lost, &queued, &pending, &failure))
                    .expect("the event writer's thread starts")
            };
            let writer = Writer {
                thread,
                pending: pending.clone(),
            };
            self.subscribe_arc(Arc::new(move |event| {
                let len = event.size();
                pending.fetch_add(1, Ordering::Relaxed);
                if queued.fetch_add(len, Ordering::Relaxed) + len > FILE_QUEUE_BYTES
                    || tx.try_send(event.clone()).is_err()
                {
                    pending.fetch_sub(1, Ordering::Relaxed);
                    queued.fetch_sub(len, Ordering::Relaxed);
                    lost.fetch_add(1, Ordering::Relaxed);
                }
            }));
            let mut s = self.store.state.lock();
            if s.closed {
                // The run is over: the thread has all it will get.
                drop(s);
                writer.join(&self.store);
            } else {
                s.writers.push(writer);
            }
        }
    }

    /// How many lines file writers lost: lines that did not fit in a
    /// writer's queue, or that a writer could not write or flush. Native
    /// writer failures are latched: this is at least one after a failure,
    /// even with no pending lines. See [`EventLog::to_writer`] for panic
    /// accounting and concurrent finalization.
    pub fn lost(&self) -> u64 {
        let lost = self.store.lost.load(Ordering::Relaxed);
        #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
        if self.store.writer_failed.load(Ordering::Relaxed) {
            return lost.max(1);
        }
        lost
    }
}

/// Owns loss accounting for the current batch, including the line in hand.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
struct WriteGuard<'a> {
    lost: &'a AtomicU64,
    failure: &'a AtomicBool,
    remaining: u64,
    unflushed: u64,
}

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.lost
                .fetch_add(self.remaining + self.unflushed, Ordering::Relaxed);
            self.failure.store(true, Ordering::Relaxed);
        }
    }
}

/// Writes the lines from `rx` to `out` until the run is over. After a
/// failed write or flush, only counts them as lost.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
fn write_lines(
    rx: Receiver<Arc<Event>>,
    mut out: Box<dyn Write + Send>,
    lost: &AtomicU64,
    queued: &AtomicUsize,
    pending: &AtomicU64,
    failure: &AtomicBool,
) {
    let mut reported = 0;
    let mut guard = WriteGuard {
        lost,
        failure,
        remaining: 0,
        unflushed: 0,
    };
    let mut failed = false;
    let mut batch = Vec::new();
    while let Ok(event) = rx.recv() {
        guard.remaining += 1;
        pending.fetch_sub(1, Ordering::Relaxed);
        batch.push(event);
        for event in rx.try_iter() {
            guard.remaining += 1;
            pending.fetch_sub(1, Ordering::Relaxed);
            batch.push(event);
        }
        for event in batch.drain(..) {
            queued.fetch_sub(event.size(), Ordering::Relaxed);
            if failed {
                lost.fetch_add(1, Ordering::Relaxed);
                guard.remaining -= 1;
                continue;
            }
            let Ok(mut line) = event.to_json().to_bytes() else {
                lost.fetch_add(1, Ordering::Relaxed);
                guard.remaining -= 1;
                continue;
            };
            line.push(b'\n');
            if out.write_all(&line).is_ok() {
                guard.unflushed += 1;
            } else {
                lost.fetch_add(guard.unflushed + 1, Ordering::Relaxed);
                guard.unflushed = 0;
                failure.store(true, Ordering::Relaxed);
                failed = true;
            }
            guard.remaining -= 1;
        }
        if !failed {
            failed = finish_batch(&mut out, lost, &mut reported, &mut guard.unflushed, failure);
        }
    }
    if !failed {
        finish_batch(&mut out, lost, &mut reported, &mut guard.unflushed, failure);
    }
}

/// Writes an `events.lost` line if more were lost since the last, then
/// flushes. Returns whether that failed, counting the unflushed lines as
/// lost if so.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
fn finish_batch(
    out: &mut Box<dyn Write + Send>,
    lost: &AtomicU64,
    reported: &mut u64,
    unflushed: &mut u64,
    failure: &AtomicBool,
) -> bool {
    let n = lost.load(Ordering::Relaxed);
    let report =
        format!("{{\"source\":\"events\",\"kind\":\"lost\",\"fields\":{{\"count\":{n}}}}}\n");
    let ok = (n == *reported || out.write_all(report.as_bytes()).is_ok()) && out.flush().is_ok();
    *reported = n;
    if ok {
        *unflushed = 0;
    } else {
        lost.fetch_add(std::mem::take(unflushed), Ordering::Relaxed);
        failure.store(true, Ordering::Relaxed);
    }
    !ok
}
