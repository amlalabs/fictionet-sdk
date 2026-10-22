//! The world's JSON-lines log at `/var/lib/fictionet/log.jsonl`.
//!
//! Network and handler events use the shared example writer. Real runs queue
//! lines without waiting on the world's thread; labs write synchronously.
//! Queue overflow produces a cumulative `lost` line so the eval can refuse
//! to score an incomplete sample.
//!
//! Repeated `blocked` lines are folded to keep a flood from writing one line
//! per packet. The first line for a sandbox, protocol, source, destination and
//! refusal reason is written immediately. Repeats within one second become
//! one line with a count and the lowest and highest destination ports.
//! The runner installs an aggregating observer before this projection. Its
//! counted lines pass through without further folding. Open folds are bounded
//! and flushed early if full.

use crate::{ServedNames, events};
use fictionet::{Cx, events::Event};
use serde_json::{Value, json};
use std::io::Write;
use std::sync::{Arc, OnceLock};
const FOLDED: &[&str] = &["blocked"];
#[derive(Clone)]
/// A handle for the world's JSON Lines log.
pub struct Log {
    inner: fictionet_extras::log::Log,
    names: Arc<OnceLock<ServedNames>>,
}
impl Log {
    /// Prepares the output. Call `attach` before writing.
    pub fn start(out: Box<dyn Write + Send>) -> std::io::Result<Self> {
        Ok(Self {
            inner: fictionet_extras::log::Log::new(out, FOLDED, transform),
            names: Arc::default(),
        })
    }
    /// Prepares the trusted harness's shutdown request and acknowledgement.
    pub fn finalization(
        &self,
        directory: &std::path::Path,
    ) -> std::io::Result<fictionet_extras::log::Finalization> {
        self.inner.finalization(directory)
    }
    /// Attaches the output to the run's lifetime. Lines judge whether an
    /// attempt left the repository against the world's `names`.
    pub fn attach(&self, fcx: &Cx, names: ServedNames) {
        self.inner.attach(fcx);
        self.names.set(names).expect("log attached once");
    }
    /// Drains the log after the run and reports output errors.
    pub fn finish(&self) -> std::io::Result<()> {
        self.inner.finish()
    }
    /// Converts a network event to a log line when it is relevant.
    pub fn entry(&self, entry: &Event) {
        let names = self.names.get().expect("log attached to a run");
        if let Some(line) = events::line(entry, names) {
            self.line(line);
        }
    }
    /// Logs a JSON object with its timestamp.
    pub fn line(&self, line: Value) {
        self.inner.write(line);
    }
}
impl fictionet::events::Observer for Log {
    fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
        let fictionet::events::Interest::Event(metadata, _) = interest else {
            return false;
        };
        events::LOGGED.contains(&metadata.source)
    }
    fn lost(&self, loss: fictionet::events::Loss) {
        if loss.stream != fictionet::events::Stream::Events {
            return;
        }
        let count = loss.count;
        if count != 0 {
            self.inner
                .write(serde_json::json!({"type": "lost", "count": count}));
            self.inner
                .fail(format!("{count} events lost before log delivery"));
        }
    }
    fn observe(
        &self,
        _: fictionet::events::Stamp,
        observation: fictionet::events::Observation<'_>,
    ) {
        if let fictionet::events::Observation::Event(event) = observation {
            self.entry(event);
        }
    }
}

fn transform(text: String) -> String {
    let mut line: Value = serde_json::from_str(&text).expect("a JSON line");
    line.as_object_mut()
        .unwrap()
        .entry("sandbox")
        .or_insert_with(|| json!({"id":0,"name":"","addr":null}));
    line.to_string()
}
#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_extras::log::fold_key;

    #[derive(Clone, Default)]
    struct Output(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Output {
        fn lines(&self) -> Vec<Value> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    #[test]
    fn gateway_dns_stays_separate_from_other_ports() {
        use fictionet::events::ConnInfo;
        use fictionet_observe::Aggregate;
        use std::sync::{Arc, atomic::AtomicUsize};
        let output = Output::default();
        let log = Arc::new(Log::start(Box::new(output.clone())).unwrap());
        let aggregate = Arc::new(Aggregate::new(log.clone()));
        let drain = log.clone();
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(aggregate),
            |cx| async move {
                log.attach(&cx, ServedNames::default());
                let open = Arc::new(AtomicUsize::new(0));
                for (id, port) in [53, 80, 53, 53, 80, 80].into_iter().enumerate() {
                    let conn = ConnInfo::new(
                        id as u64,
                        ([10, 0, 0, 1], port).into(),
                        ([10, 0, 0, 2], 1234).into(),
                    );
                    assert!(
                        fictionet::stdlib::world::net::connection_limit(&cx, &conn, &open, 0)
                            .is_none()
                    );
                }
                Ok(())
            },
        ))
        .unwrap();
        drain.finish().unwrap();
        let lines = output.lines();
        for (port, count) in [(53, 3), (80, 3)] {
            let matching: u64 = lines
                .iter()
                .filter(|line| line["dst_port"] == port || line["ports"] == json!([port, port]))
                .map(|line| line["count"].as_u64().unwrap_or(1))
                .sum();
            assert_eq!(matching, count);
        }
        assert!(lines.iter().all(|line| line["ports"] != json!([53, 80])));
    }

    #[test]
    fn producer_loss_prevents_successful_finalization() {
        let output = Output::default();
        let log = Log::start(Box::new(output.clone())).unwrap();
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| {
                log.attach(&cx, ServedNames::default());
                fictionet::events::Observer::lost(
                    &log,
                    fictionet::events::Loss::staged(fictionet::events::Stream::Events, 3),
                );
                async { Ok(()) }
            },
        ))
        .unwrap();
        assert_eq!(
            log.finish().unwrap_err().to_string(),
            "3 events lost before log delivery"
        );
        let lines = output.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["type"], "lost");
        assert_eq!(lines[0]["count"], 3);
    }

    /// The observer's counted `blocked` lines are written as they come,
    /// not counted again.
    #[test]
    fn counted_lines_are_not_folded_again() {
        let first = json!({
            "type": "blocked", "sandbox": {"id": 1}, "why": "ClosedPort",
            "src": "10.0.0.2", "dst": "84.21.44.10", "dst_port": 1,
        });
        let counted = json!({
            "type": "blocked", "sandbox": {"id": 1}, "why": "ClosedPort",
            "src": "10.0.0.2", "dst": "84.21.44.10", "count": 999, "ports": [2, 1000],
        });
        assert!(fold_key(first.as_object().unwrap(), FOLDED).is_some());
        assert_eq!(fold_key(counted.as_object().unwrap(), FOLDED), None);
    }

    #[test]
    fn repeated_lines_fold_into_a_count() {
        fictionet_extras::log::assert_repeated_lines_fold(FOLDED, transform);
    }
}
