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
//! Open folds are bounded and flushed early if full. Typed callbacks retain
//! individual attempts so consumers can choose their own presentation.

use crate::{
    ServedNames, events,
    facts::{self, Door, Request},
};
use fictionet::{
    Cx,
    stdlib::{services::dns, web::httpd, world::net},
};
use serde_json::{Value, json};
use std::io::Write;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};
const FOLDED: &[&str] = &["blocked"];
type Observe = Arc<dyn Fn(&facts::Observation) + Send + Sync>;

#[derive(Clone)]
/// A handle for the world's JSON Lines log and typed observations.
pub struct Log {
    inner: fictionet_extras::log::Log,
    names: Arc<OnceLock<ServedNames>>,
    sequence: Arc<AtomicU64>,
    observe: Option<Observe>,
}
impl Log {
    /// Prepares the output. Call `attach` before writing.
    pub fn start(out: Box<dyn Write + Send>) -> std::io::Result<Self> {
        Ok(Self {
            inner: fictionet_extras::log::Log::new(out, FOLDED, transform),
            names: Arc::default(),
            sequence: Arc::default(),
            observe: None,
        })
    }
    /// Receives each typed request or door fact directly from its owner.
    /// The JSON writer folds repeated blocked lines; callbacks retain each attempt.
    pub fn observe(
        mut self,
        observe: impl Fn(&facts::Observation) + Send + Sync + 'static,
    ) -> Self {
        self.observe = Some(Arc::new(observe));
        self
    }
    /// Prepares the trusted harness's shutdown request and acknowledgement.
    pub fn finalization(
        &self,
        directory: &std::path::Path,
    ) -> std::io::Result<fictionet_extras::log::Finalization> {
        self.inner.finalization(directory)
    }
    /// Attaches the output to the run's lifetime and served names.
    pub fn attach(&self, fcx: &Cx, names: ServedNames) {
        self.inner.attach(fcx);
        self.names.set(names).expect("log attached once");
    }
    /// Drains the log after the run and reports output errors.
    pub fn finish(&self) -> std::io::Result<()> {
        self.inner.finish()
    }
    fn next(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed) + 1
    }
    fn record(&self, observation: facts::Observation, mut line: Value) {
        if let Some(door) = &observation.door {
            line["left"] = json!(door.egress_denied);
        }
        if let Some(observe) = &self.observe {
            observe(&observation);
        }
        self.line(line);
    }
    /// Records an HTTP exchange after delivery completes or is interrupted.
    pub fn http(&self, event: httpd::Observation) {
        let seq = self.next();
        let observation = facts::Observation {
            at: event.at,
            conn: event.conn.clone(),
            request: Some(Request::from_http(seq, &event)),
            door: Some(Door::from_http(seq, &event)),
        };
        self.record(observation, events::http(&event));
    }
    /// Records a completed TLS handshake attempt.
    pub fn tls(&self, event: &net::TlsObservation) {
        let door = Door::from_tls(
            self.next(),
            event,
            self.names.get().expect("log attached to a run"),
        );
        self.record(
            facts::Observation {
                at: event.at,
                conn: event.conn.clone(),
                request: None,
                door: Some(door),
            },
            events::tls(event),
        );
    }
    /// Records a refused packet.
    pub fn refused(&self, event: &net::RefusedPacket) {
        self.record(
            facts::Observation {
                at: event.at,
                conn: event.conn.clone(),
                request: None,
                door: Some(Door::from_refused(self.next(), event)),
            },
            events::refused(event),
        );
    }
    /// Records DNS replies to clients, leaving internal engine work out of the log.
    pub fn dns(&self, event: &dns::Event) {
        if let dns::Event::Reply { at, .. } = event
            && let Some(line) = events::dns(event)
            && let Some(conn) = events::dns_conn(event)
            && let Some(door) = Door::from_dns(self.next(), event)
        {
            self.record(
                facts::Observation {
                    at: *at,
                    conn,
                    request: None,
                    door: Some(door),
                },
                line,
            );
        }
    }
    /// Records attachment lifetime and address changes.
    pub fn attachment(&self, event: &net::AttachmentObservation) {
        self.line(events::attachment(event));
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
    use fictionet_extras::log::fold_key;

    #[test]
    fn output_failure_prevents_successful_finalization() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("output closed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let log = Log::start(Box::new(Broken)).unwrap();
        fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(1), |cx| {
            log.attach(&cx, ServedNames::default());
            log.line(json!({"type":"http"}));
            async { Ok(()) }
        }))
        .unwrap();
        assert!(log.finish().is_err());
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
