//! A bounded copy of the actual JSON lines written by the world's log.
//! This writer sits after the log's redaction and folding. It does not score
//! traffic or reconstruct log entries from observations.

use fictionet_observe::page::{StateLimits, StateTopic};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::VecDeque,
    io::{self, Write},
};

const LINE_BYTES: usize = 8192;
const ROWS: usize = 32;
#[derive(Clone, Default, Serialize)]
pub struct Results {
    pub first_ts: Option<f64>,
    pub lines: VecDeque<Value>,
    pub dropped: u64,
    pub invalid: u64,
}
pub struct Writer<W> {
    out: W,
    topic: StateTopic<Results>,
    view: Results,
    line: Vec<u8>,
    oversized: bool,
}
impl<W: Write> Writer<W> {
    pub fn new(out: W, topic: StateTopic<Results>) -> Self {
        Self {
            out,
            topic,
            view: Results::default(),
            line: vec![],
            oversized: false,
        }
    }
    pub fn topic() -> StateTopic<Results> {
        StateTopic::new(StateLimits {
            max_bytes: (ROWS + 1) * LINE_BYTES,
            deltas: 0,
        })
    }
    fn line(&mut self) {
        if self.oversized {
            self.view.dropped += 1;
        } else {
            match serde_json::from_slice::<Value>(&self.line) {
                Ok(value) => {
                    if self.view.first_ts.is_none() {
                        self.view.first_ts = value["ts"].as_f64();
                    }
                    if matches!(
                        value["type"].as_str(),
                        Some("tls" | "route" | "route_rejected" | "lost")
                    ) || value["type"] == "http" && value["served_by"] == "impostor"
                    {
                        if self.view.lines.len() == ROWS {
                            self.view.lines.pop_front();
                            self.view.dropped += 1;
                        }
                        self.view.lines.push_back(value);
                    }
                }
                Err(_) => self.view.invalid += 1,
            }
        }
        self.line.clear();
        self.oversized = false;
        let _ = self
            .topic
            .publish(fictionet::time::Instant::ZERO, &self.view);
    }
}
impl<W: Write> Write for Writer<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.out.write(bytes)?;
        for &byte in &bytes[..n] {
            if byte == b'\n' {
                self.line();
            } else if self.line.len() < LINE_BYTES && !self.oversized {
                self.line.push(byte);
            } else {
                self.oversized = true;
                self.line.clear();
            }
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_writes_preserve_the_log_and_limit_the_copy() {
        let topic = Writer::<Vec<u8>>::topic();
        let mut writer = Writer::new(Vec::new(), topic);
        let bytes = b"{\"type\":\"route\",\"revision\":1}\n";
        for byte in bytes {
            writer.write_all(&[*byte]).unwrap();
        }
        assert_eq!(writer.out, bytes);
        assert_eq!(writer.view.lines[0]["revision"], 1);
        for _ in 0..40 {
            writer.write_all(bytes).unwrap();
        }
        assert_eq!(writer.view.lines.len(), ROWS);
        assert_eq!(writer.view.dropped, 9);
        writer.write_all(&vec![b'x'; LINE_BYTES + 1]).unwrap();
        writer.write_all(b"\n").unwrap();
        assert_eq!(writer.view.dropped, 10);
        assert_eq!(writer.view.invalid, 0);
        writer.write_all(b"broken\n").unwrap();
        assert_eq!(writer.view.invalid, 1);
    }
}
