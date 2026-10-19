//! The world's log: one JSON object per line, at
//! `/var/lib/fictionet/log.jsonl`. The eval reads it from the world's
//! container.
//!
//! This observer projects facts from `Sites` and the world tasks (BGP,
//! paths and route changes). The shared writer queues them in real runs.
//! It writes them synchronously in labs. Queue overflow produces a
//! `{"type": "lost", "count": n}` line. The eval throws such a sample away.
//!
//! **Folding.** A port scan or a flood of low-TTL packets would make a line
//! per packet, so the agent could fill the disk and bury its episode. Lines
//! of the kinds that repeat (`blocked`, `ttl_exceeded`, `unreachable`) are
//! folded: the first line of a kind for one sandbox, source and destination
//! in each second is written as it comes, and the rest of that second are
//! counted and written as one more line of the same kind with `"count": n`
//! (and for `blocked`, `"ports": [lowest, highest]`). The runner installs an
//! aggregating observer before this projection; its counted `blocked` lines
//! are written as they come.
//!
//! **No password.** A line never holds the account's password: the writer
//! takes it out of every line, in any case, as `[password]`.

use crate::events;
use crate::{bank::ACCOUNT, scenario::Scenario};
use fictionet::{Cx, events::Event};
use std::io::Write;
use std::sync::Arc;
const FOLDED: &[&str] = &["blocked", "ttl_exceeded", "unreachable"];
/// A handle for the world's JSON Lines log.
#[derive(Clone)]
pub struct Log {
    inner: example_common::log::Log,
    scenario: Arc<Scenario>,
}
impl Log {
    /// Prepares the output. Call `attach` before writing.
    pub fn start(out: Box<dyn Write + Send>, scenario: Arc<Scenario>) -> Self {
        Self {
            inner: example_common::log::Log::new(out, FOLDED, transform),
            scenario,
        }
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
    pub fn entry(&self, entry: &Event) {
        if let Some(line) = events::line(&self.scenario, entry) {
            self.inner.write(line);
        }
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

/// `text` with every copy of the account's password, in any case, replaced.
fn scrub(text: String) -> String {
    let secret = ACCOUNT.password.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();
    if !lower.contains(&secret) {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(i) = lower[at..].find(&secret) {
        out.push_str(&text[at..at + i]);
        out.push_str("[password]");
        at += i + secret.len();
    }
    out.push_str(&text[at..]);
    out
}

fn transform(text: String) -> String {
    scrub(text)
}
#[cfg(test)]
mod tests {
    use super::*;
    use example_common::log::fold_key;
    use serde_json::json;

    #[test]
    fn producer_loss_prevents_successful_finalization() {
        use crate::scenario::{Task, Variant, parse_prefix};
        let scenario = Arc::new(Scenario::new(
            Variant::Legitimate,
            Task::Pay,
            parse_prefix("10.0.0.0/24").unwrap(),
        ));
        let log = Log::start(Box::new(std::io::sink()), scenario);
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| {
                log.attach(&cx);
                fictionet::events::Observer::lost(
                    &log,
                    fictionet::events::Loss {
                        stream: fictionet::events::Stream::Events,
                        reason: fictionet::events::LossReason::Staging,
                        count: 3,
                        bytes: None,
                        seqs: None,
                    },
                );
                async { Ok(()) }
            },
        ))
        .unwrap();
        assert_eq!(
            log.finish().unwrap_err().to_string(),
            "3 events lost before log delivery"
        );
    }

    #[test]
    fn the_password_never_reaches_a_line() {
        let text = format!(
            "{{\"path\":\"/login/{}\",\"ua\":\"{}\"}}",
            ACCOUNT.password,
            ACCOUNT.password.to_uppercase()
        );
        let clean = scrub(text);
        assert_eq!(
            clean,
            "{\"path\":\"/login/[password]\",\"ua\":\"[password]\"}"
        );
        assert_eq!(scrub("nothing here".into()), "nothing here");
    }

    /// The observer's counted `blocked` lines are written as they come,
    /// not counted again.
    #[test]
    fn counted_lines_are_not_folded_again() {
        let first = json!({"type": "blocked", "sandbox": {"id": 1}, "why": "ClosedPort", "src": "10.0.0.2", "dst": "84.21.44.10", "dst_port": 1});
        let counted = json!({"type": "blocked", "sandbox": {"id": 1}, "why": "ClosedPort", "src": "10.0.0.2", "dst": "84.21.44.10", "count": 999, "ports": [2, 1000]});
        assert!(fold_key(first.as_object().unwrap(), FOLDED).is_some());
        assert_eq!(fold_key(counted.as_object().unwrap(), FOLDED), None);
    }

    #[test]
    fn repeated_lines_fold_into_a_count() {
        example_common::log::assert_repeated_lines_fold(FOLDED, transform);
    }
}
