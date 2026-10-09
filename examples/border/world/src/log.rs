//! The world's log: one JSON object per line, at
//! `/var/lib/fictionet/log.jsonl`. The eval reads it from the world's
//! container.
//!
//! Lines come from `Sites`' events and from the world's own tasks (BGP,
//! the hops). The shared writer queues them in real runs and writes
//! them synchronously in labs. Queue overflow produces a
//! `{"type": "lost", "count": n}` line. The eval throws such a sample away.
//!
//! **Folding.** A port scan or a flood of low-TTL packets would make a line
//! per packet, so the agent could fill the disk and bury its episode. Lines
//! of the kinds that repeat (`blocked`, `ttl_exceeded`, `unreachable`) are
//! folded: the first line of a kind for one sandbox, source and destination
//! in each second is written as it comes, and the rest of that second are
//! counted and written as one more line of the same kind with `"count": n`
//! (and for `blocked`, `"ports": [lowest, highest]`). The network already
//! counts the packets it blocks the same way, so its counted `blocked`
//! lines are written as they come.
//!
//! **No password.** A line never holds the account's password: the writer
//! takes it out of every line, in any case, as `[password]`.

use crate::events;
use fictionet::{Cx, events::Event as Entry};
use serde_json::Value;
use std::io::Write;
use std::sync::Arc;
#[path = "../../../common/log.rs"]
mod shared;
use crate::{bank::ACCOUNT, scenario::Scenario};
const FOLDED: &[&str] = &["blocked", "ttl_exceeded", "unreachable"];
/// A handle for the world's JSON Lines log.
#[derive(Clone)]
pub struct Log {
    inner: shared::Log,
    scenario: Arc<Scenario>,
}
impl Log {
    /// Prepares the output. Call `attach` before writing.
    pub fn start(out: Box<dyn Write + Send>, scenario: Arc<Scenario>) -> Self {
        Self {
            inner: shared::Log::new(out, FOLDED, transform),
            scenario,
        }
    }
    /// Attaches the output to the run's lifetime.
    pub fn attach(&self, fcx: &Cx) {
        self.inner.attach(fcx);
    }
    /// Converts a network event to a log line when it is relevant.
    pub fn entry(&self, entry: &Entry) {
        if let Some(line) = events::line(&self.scenario, entry) {
            self.line(line);
        }
    }
    /// Logs a JSON object with its timestamp.
    pub fn line(&self, line: Value) {
        self.inner.write(line);
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
    use serde_json::json;
    use shared::fold_key;

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

    /// The network's own counted `blocked` lines are written as they come,
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
        shared::assert_repeated_lines_fold(FOLDED, transform);
    }
}
