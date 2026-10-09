//! The request log: one JSON object per line, at
//! /var/lib/fictionet/log.jsonl. The eval reads it with
//! `docker compose exec fictionet cat`.

#[path = "../../../common/log.rs"]
mod shared;
/// A handle for the world's JSON Lines log.
pub struct Log(shared::Log);
impl Log {
    /// Opens the log file and empties its previous contents.
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self(shared::Log::new(
            Box::new(std::fs::File::create(path)?),
            &[],
            |s| s,
        )))
    }
    /// Attaches the output to the run's event writer.
    pub fn attach(&self, fcx: &fictionet::Cx) {
        self.0.attach(fcx);
    }
    /// Logs a JSON object with its timestamp.
    pub fn write(&self, line: serde_json::Value) {
        self.0.write(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::mpsc::{self, Sender};
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
        let (recorded, returned) = mpsc::channel();
        let callback = std::thread::spawn(move || {
            fictionet::block_on(fictionet::run(
                fictionet::Seed::from_u64(1),
                move |fcx| async move {
                    let log = shared::Log::new(
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
}
