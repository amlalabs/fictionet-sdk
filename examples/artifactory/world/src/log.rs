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
//! The network also folds packets. Its already-counted lines pass through
//! without further folding. Open folds are bounded and flushed early if full.

use crate::events;
use fictionet::{Cx, events::Event as Entry};
use serde_json::{Value, json};
use std::io::Write;
const FOLDED: &[&str] = &["blocked"];
#[derive(Clone)]
/// A handle for the world's JSON Lines log.
pub struct Log {
    inner: example_common::log::Log,
}
impl Log {
    /// Prepares the output. Call `attach` before writing.
    pub fn start(out: Box<dyn Write + Send>) -> std::io::Result<Self> {
        Ok(Self {
            inner: example_common::log::Log::new(out, FOLDED, transform),
        })
    }
    /// Prepares the trusted harness's shutdown request and acknowledgement.
    pub fn finalization(
        &self,
        directory: &std::path::Path,
    ) -> std::io::Result<example_common::log::Finalization> {
        self.inner.finalization(directory)
    }
    /// Attaches the output to the run's lifetime.
    pub fn attach(&self, fcx: &Cx) {
        self.inner.attach(fcx);
    }
    /// Drains the log after the run and reports output errors.
    pub fn finish(&self) -> std::io::Result<()> {
        self.inner.finish()
    }
    /// Converts a network event to a log line when it is relevant.
    pub fn entry(&self, entry: &Entry) {
        if let Some(line) = events::line(entry) {
            self.line(line);
        }
    }
    /// Logs a JSON object with its timestamp.
    pub fn line(&self, line: Value) {
        self.inner.write(line);
    }
}
impl fictionet::events::Observer for Log {
    fn enabled(
        &self,
        metadata: fictionet::events::Metadata,
        _: &fictionet::events::ConnInfo,
    ) -> bool {
        events::LOGGED.contains(&metadata.source)
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
    use example_common::log::fold_key;

    /// The network's own counted `blocked` lines are written as they come,
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
        example_common::log::assert_repeated_lines_fold(FOLDED, transform);
    }
}
