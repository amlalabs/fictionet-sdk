//! The world's JSON-lines log at `/var/lib/fictionet/log.jsonl`.
//!
//! Network and handler events use the run's event writer. Real runs queue
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
#[path = "../../../common/log.rs"]
mod shared;
const FOLDED: &[&str] = &["blocked"];
#[derive(Clone)]
/// A handle for the world's JSON Lines log.
pub struct Log {
    inner: shared::Log,
}
impl Log {
    /// Prepares the output. Call `attach` before writing.
    pub fn start(out: Box<dyn Write + Send>) -> std::io::Result<Self> {
        Ok(Self {
            inner: shared::Log::new(out, FOLDED, transform),
        })
    }
    /// Attaches the output to the run's event writer.
    pub fn attach(&self, fcx: &Cx) {
        self.inner.attach(fcx);
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
    use shared::{Writer, fold_key};

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
        let blocked = |port: u16| {
            json!({
                "type": "blocked", "sandbox": {"id": 1, "name": "a"},
                "why": "Refused", "protocol": 6,
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
        let mut w = Writer::new(Box::new(Out(buf.clone())), FOLDED, transform);
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
}
