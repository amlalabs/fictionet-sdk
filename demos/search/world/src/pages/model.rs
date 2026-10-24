//! Model calls: Anthropic's Messages API and OpenRouter's OpenAI-compatible
//! chat completions, over the SDK's own HTTP client ([`fictionet::stdlib::web::forward`]).
//!
//! A [`Model`] answers one prompt at a time. Each call keeps a [`Ledger`]
//! of its HTTP attempts: retryable failures (rate limits, overloaded or
//! failing servers, transport errors and unreadable responses) get at most
//! three attempts, 1.5 s and 3 s apart. An answer the world cannot read is
//! asked for once more with the reason. Every attempt becomes a row of the
//! store's `generations.jsonl`, and the last row of a generation carries
//! its totals.
//!
//! The key comes from `ANTHROPIC_API_KEY` or `OPENROUTER_API_KEY`. It must
//! be printable ASCII, is sent in the request's header and nowhere else,
//! and is replaced by the variable's name in every error message.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fictionet::Cx;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::prompts::Unreadable;
use fictionet_extras::models::{Key, Transport};

impl From<Provider> for fictionet_extras::models::Provider {
    fn from(provider: Provider) -> Self {
        match provider {
            Provider::Anthropic => Self::Anthropic,
            Provider::OpenRouter => Self::OpenRouter,
        }
    }
}

/// Answers worth asking again: rate limits and overloaded or failing servers.
const RETRY: [u16; 7] = [408, 429, 500, 502, 503, 504, 529];
/// The most HTTP attempts for one answer.
const ATTEMPTS: u32 = 3;
/// How long one HTTP attempt may take.
const TIMEOUT: Duration = Duration::from_secs(120);

/// A model API selected by the world configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    OpenRouter,
}

impl Provider {
    /// The variable that holds the provider's key.
    pub fn key_variable(self) -> &'static str {
        match self {
            Self::Anthropic => "ANTHROPIC_API_KEY",
            Self::OpenRouter => "OPENROUTER_API_KEY",
        }
    }
    /// The model used when none is named.
    pub fn default_model(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-haiku-4-5-20251001",
            Self::OpenRouter => "google/gemini-3.1-flash-lite",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenRouter => "OpenRouter",
        }
    }
}

/// The outcome of one provider attempt, rendered to words at the record boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    Transport,
    Ok,
    Unreadable,
    Http(u16),
}
impl Serialize for AttemptOutcome {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Transport => serializer.serialize_str("transport"),
            Self::Ok => serializer.serialize_str("ok"),
            Self::Unreadable => serializer.serialize_str("unreadable"),
            Self::Http(status) => serializer.serialize_str(&format!("http {status}")),
        }
    }
}

/// One HTTP attempt. Times are seconds on the run's clock.
#[derive(Clone, Debug, Serialize)]
pub struct Attempt {
    pub ask: u32,
    pub attempt: u32,
    pub started: f64,
    pub ended: f64,
    pub outcome: AttemptOutcome,
    pub model: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost: Option<f64>,
    pub raw: Option<String>,
    pub cut_off: bool,
    pub backoff_ms: u64,
    pub error: Option<String>,
}

impl Attempt {
    fn ms(&self) -> u64 {
        ((self.ended - self.started) * 1000.0).round() as u64
    }
}

/// What a generation cost: time, attempts, tokens and money. A total is
/// unknown (`None`) if any attempt's value was not reported.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    pub model: String,
    /// From the first HTTP attempt through reading the final answer,
    /// including backoff and re-asks.
    pub gen_ms: u64,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// US dollars.
    pub cost: Option<f64>,
    /// The final answer stopped at its token budget.
    pub cut_off: bool,
    /// The accepted answer's HTTP call alone.
    pub call_ms: Option<u64>,
    pub attempts: u64,
    /// Prompts sent, including the first.
    pub asks: u64,
    /// The sum of the reported costs.
    pub cost_known: f64,
    /// Attempts without a reported cost.
    pub cost_unknown: u64,
    pub backoff_ms: u64,
}

impl Usage {
    /// One stored response that took `ms`.
    pub fn stored(ms: u64) -> Self {
        Self {
            model: "stored".into(),
            gen_ms: ms,
            input_tokens: None,
            output_tokens: None,
            cost: None,
            cut_off: false,
            call_ms: Some(ms),
            attempts: 1,
            asks: 1,
            cost_known: 0.0,
            cost_unknown: 1,
            backoff_ms: 0,
        }
    }
}

fn total<T: std::iter::Sum<T> + Copy>(values: impl Iterator<Item = Option<T>>) -> Option<T> {
    values
        .collect::<Option<Vec<T>>>()
        .map(|v| v.into_iter().sum())
}

/// Every HTTP attempt of one generation, across its re-asks.
#[derive(Debug)]
pub struct Ledger {
    pub attempts: Vec<Attempt>,
    ask: u32,
    ended: Option<f64>,
}

fn now(cx: &Cx) -> f64 {
    cx.now().since_start().as_secs_f64()
}

impl Ledger {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            ask: 1,
            ended: None,
        }
    }

    /// The generation's totals so far.
    pub fn usage(&self) -> Usage {
        let first = self.attempts.first().expect("an attempt");
        let last = self.attempts.last().expect("an attempt");
        let ended = self.ended.unwrap_or(last.ended);
        Usage {
            model: last.model.clone(),
            gen_ms: ((ended - first.started) * 1000.0).round() as u64,
            call_ms: (last.outcome == AttemptOutcome::Ok).then(|| last.ms()),
            attempts: self.attempts.len() as u64,
            asks: u64::from(self.ask),
            backoff_ms: self.attempts.iter().map(|a| a.backoff_ms).sum(),
            input_tokens: total(self.attempts.iter().map(|a| a.input_tokens)),
            output_tokens: total(self.attempts.iter().map(|a| a.output_tokens)),
            cost: total(self.attempts.iter().map(|a| a.cost)),
            cost_known: self.attempts.iter().filter_map(|a| a.cost).sum(),
            cost_unknown: self.attempts.iter().filter(|a| a.cost.is_none()).count() as u64,
            cut_off: last.cut_off,
        }
    }

    /// One row per attempt, with `context` (`kind` and the query or URL).
    /// The last also carries the generation's totals and `status`.
    pub fn rows(&self, context: &Value, status: &str) -> Vec<Value> {
        let count = self.attempts.len();
        self.attempts
            .iter()
            .enumerate()
            .map(|(index, attempt)| {
                let mut row = context.clone();
                row["record"] = json!("attempt");
                for (key, value) in serde_json::to_value(attempt).unwrap().as_object().unwrap() {
                    row[key] = value.clone();
                }
                row["ms"] = json!(attempt.ms());
                row["terminal"] = json!(index + 1 == count);
                if index + 1 == count {
                    let mut generation = serde_json::to_value(self.usage()).unwrap();
                    generation["status"] = json!(status);
                    row["gen_ms"] = generation["gen_ms"].clone();
                    row["generation"] = generation;
                }
                row
            })
            .collect()
    }
}

/// A failed model call: why, with every attempt kept for the ledger.
#[derive(Debug)]
pub struct Failure {
    pub error: String,
    pub rejection: Option<Unreadable>,
}

impl Failure {
    pub(super) fn can_render_locally(&self) -> bool {
        matches!(
            self.rejection,
            Some(Unreadable::Disclosure(_) | Unreadable::Incomplete | Unreadable::Content(_))
        )
    }
}

/// What a store made with a model records: provider, model (an empty one
/// is the provider's default) and reasoning, which together decide how
/// pages are written.
pub fn identity(provider: Provider, model: &str, reasoning: &str) -> Value {
    let model = if model.is_empty() {
        provider.default_model()
    } else {
        model
    };
    json!({"provider": provider, "model": model, "reasoning": reasoning})
}

/// A model and how to reach it.
pub struct Model {
    pub provider: Provider,
    pub model: String,
    /// The reasoning effort, or empty for the provider default.
    pub reasoning: String,
    key: Key,
    transport: fictionet_extras::models::Authenticated,
    live: Option<Arc<AtomicUsize>>,
}

/// A read answer, with the raw text the model gave.
pub struct Answer<T> {
    pub fields: T,
    pub raw: String,
}

mod transport;
use transport::ProviderTransport;

impl Model {
    /// The default page writer, using the existing OpenRouter credential.
    pub fn openrouter() -> Result<Self, String> {
        Ok(Self::new(
            Provider::OpenRouter,
            "",
            "",
            Key::from_env(fictionet_extras::models::Provider::OpenRouter)?,
            Arc::new(ProviderTransport::new(Provider::OpenRouter)),
        ))
    }

    /// The default page writer with the host's Anthropic API credential.
    pub fn anthropic() -> Result<Self, String> {
        Ok(Self::new(
            Provider::Anthropic,
            "",
            "",
            Key::from_env(fictionet_extras::models::Provider::Anthropic)?,
            Arc::new(ProviderTransport::new(Provider::Anthropic)),
        ))
    }

    /// Uses the same host-held Claude subscription credential as the guest gateway.
    pub fn claude_token(key: Key) -> Self {
        Self::new(
            Provider::Anthropic,
            "claude-sonnet-5-5",
            "low",
            key,
            Arc::new(ProviderTransport::new(Provider::Anthropic)),
        )
    }

    /// A model of `provider`; an empty `model` is the provider's default.
    pub fn new(
        provider: Provider,
        model: &str,
        reasoning: &str,
        key: Key,
        transport: Arc<dyn Transport>,
    ) -> Self {
        let model = if model.is_empty() {
            provider.default_model()
        } else {
            model
        };
        Self {
            provider,
            model: model.into(),
            reasoning: reasoning.into(),
            transport: fictionet_extras::models::Authenticated::new(key.clone(), transport),
            key,
            live: None,
        }
    }

    /// Installs observation on the reusable provider transport.
    pub fn observe_upstream(&self, observer: Arc<fictionet_extras::models::UpstreamObserver>) {
        self.transport.observe_upstream(observer);
    }

    /// A shared call cap for an interactive world.
    pub(super) fn live(mut self, calls: Arc<AtomicUsize>) -> Self {
        self.live = Some(calls);
        self
    }

    /// What a store made with this model records. See [`identity`].
    pub fn identity(&self) -> Value {
        identity(self.provider, &self.model, &self.reasoning)
    }

    /// `text` without the key.
    pub fn redact(&self, text: &str) -> String {
        self.key.redact(text)
    }

    /// Every string in `value` without the key.
    pub fn redact_json(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.redact(text),
            Value::Array(items) => items.iter_mut().for_each(|v| self.redact_json(v)),
            Value::Object(members) => members.values_mut().for_each(|v| self.redact_json(v)),
            _ => {}
        }
    }

    fn request(
        &self,
        system: &str,
        user: &str,
        max_tokens: u32,
    ) -> (Vec<(&'static str, String)>, Value) {
        match self.provider {
            Provider::Anthropic => {
                let mut headers = vec![
                    self.key.header(self.provider.into()),
                    ("anthropic-version", "2023-06-01".into()),
                    ("content-type", "application/json".into()),
                ];
                let system = if self.key.is_claude_token() {
                    headers.push(("anthropic-beta", "oauth-2025-04-20".into()));
                    json!([
                        {"type":"text", "text":"You are Claude Code, Anthropic's official CLI for Claude."},
                        {"type":"text", "text":system}
                    ])
                } else {
                    json!(system)
                };
                let mut body = json!({
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "system": system,
                    "messages": [{"role":"user", "content":user}],
                });
                if !self.reasoning.is_empty() {
                    body["output_config"] = json!({"effort":self.reasoning});
                    body["thinking"] = json!({"type":"between_tools"});
                }
                (headers, body)
            }
            Provider::OpenRouter => {
                let mut body = json!({
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "temperature": 1.0,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "usage": {"include": true},
                    // The fastest provider that serves the model, not the cheapest.
                    "provider": {"sort": "throughput"},
                });
                if !self.reasoning.is_empty() {
                    body["reasoning"] = json!({"effort": self.reasoning});
                }
                (
                    vec![
                        self.key.header(self.provider.into()),
                        ("content-type", "application/json".into()),
                        ("x-title", "Fictionet web".into()),
                    ],
                    body,
                )
            }
        }
    }

    /// POSTs one prompt, retrying what is worth retrying, and returns the
    /// answer's JSON with its attempt as the ledger's last.
    async fn post(
        &self,
        cx: &Cx,
        body: &Value,
        headers: &[(&'static str, String)],
        ledger: &mut Ledger,
    ) -> Result<Value, Failure> {
        let what = format!("{} {}", self.provider.label(), self.model);
        let data = serde_json::to_vec(body).expect("a JSON value");
        let mut failure = String::new();
        let attempts = if self.live.is_some() { 1 } else { ATTEMPTS };
        let elapsed = ledger.attempts.first().map_or(0.0, |a| now(cx) - a.started);
        let timeout = TIMEOUT.saturating_sub(Duration::from_secs_f64(elapsed));
        let deadline = cx.now() + timeout;
        for index in 1..=attempts {
            let mut attempt = Attempt {
                ask: ledger.ask,
                attempt: index,
                started: now(cx),
                ended: 0.0,
                outcome: AttemptOutcome::Transport,
                model: self.model.clone(),
                input_tokens: None,
                output_tokens: None,
                cost: None,
                raw: None,
                cut_off: false,
                backoff_ms: 0,
                error: None,
            };
            let sent = cx
                .race(
                    Some(deadline),
                    self.transport.post(cx, headers.to_vec(), data.clone()),
                )
                .await;
            attempt.ended = now(cx);
            let mut retry = true;
            match sent {
                Ok(Ok((status, reply))) if (200..300).contains(&status) => {
                    match serde_json::from_slice::<Value>(&reply) {
                        Ok(answer) if answer.is_object() => {
                            usage(&answer, &mut attempt);
                            attempt.outcome = AttemptOutcome::Ok;
                            ledger.attempts.push(attempt);
                            ledger.ended = Some(now(cx));
                            return Ok(answer);
                        }
                        Ok(_) => {
                            attempt.outcome = AttemptOutcome::Unreadable;
                            failure = "the model's response is not a JSON object".into();
                        }
                        Err(error) => {
                            attempt.outcome = AttemptOutcome::Unreadable;
                            failure = format!("the model's response is not JSON: {error}");
                        }
                    }
                }
                Ok(Ok((status, reply))) => {
                    attempt.outcome = AttemptOutcome::Http(status);
                    let detail = self.redact(&String::from_utf8_lossy(&reply));
                    let mut end = detail.len().min(400);
                    while !detail.is_char_boundary(end) {
                        end -= 1;
                    }
                    failure = format!("HTTP {status}: {}", &detail[..end]);
                    match serde_json::from_slice::<Value>(&reply) {
                        Ok(answer) => usage(&answer, &mut attempt),
                        Err(error) => {
                            failure.push_str(&format!(" (unreadable error response: {error})"));
                        }
                    }
                    retry = RETRY.contains(&status);
                }
                Ok(Err(error)) => failure = self.redact(&error),
                Err(fictionet::RaceError::Deadline) => {
                    failure = format!("no answer within {} s", timeout.as_secs());
                }
                Err(fictionet::RaceError::Cancelled) => {
                    failure = "the world stopped".into();
                    retry = false;
                }
            }
            attempt.error = Some(failure.clone());
            ledger.attempts.push(attempt);
            ledger.ended = Some(now(cx));
            if !retry || index == attempts {
                break;
            }
            let started = cx.now().since_start();
            let backoff = Duration::from_millis(1500 * u64::from(index));
            let slept = cx.sleep(backoff).await;
            let last = ledger.attempts.last_mut().expect("an attempt");
            last.backoff_ms = (cx.now().since_start() - started).as_millis() as u64;
            ledger.ended = Some(now(cx));
            if slept.is_err() {
                break;
            }
        }
        Err(Failure {
            error: self.redact(&format!("{what} failed: {failure}")),
            rejection: None,
        })
    }

    /// One answer's text: the ledger's last attempt keeps it, and whether
    /// it stopped at `max_tokens`.
    async fn complete(
        &self,
        cx: &Cx,
        system: &str,
        user: &str,
        max_tokens: u32,
        ledger: &mut Ledger,
    ) -> Result<String, Failure> {
        let (headers, body) = self.request(system, user, max_tokens);
        let answer = self.post(cx, &body, &headers, ledger).await?;
        let attempt = ledger.attempts.last_mut().expect("an attempt");
        let what = format!("{} {}", self.provider.label(), self.model);
        let unreadable = |attempt: &mut Attempt, error: String| {
            attempt.outcome = AttemptOutcome::Unreadable;
            attempt.error = Some(error.clone());
            Failure {
                error,
                rejection: None,
            }
        };
        let (text, cut_off) = match self.provider {
            Provider::Anthropic => {
                let Some(blocks) = answer["content"].as_array() else {
                    let error = self.redact(&format!("{what}: unreadable response"));
                    return Err(unreadable(attempt, error));
                };
                let text: String = blocks
                    .iter()
                    .filter(|b| b["type"] == "text")
                    .filter_map(|b| b["text"].as_str())
                    .collect();
                (text, answer["stop_reason"] == "max_tokens")
            }
            Provider::OpenRouter => {
                if let Some(error) = answer.get("error") {
                    let detail: String =
                        self.redact(&error.to_string()).chars().take(400).collect();
                    let error = self.redact(&format!("{what} failed: {detail}"));
                    return Err(unreadable(attempt, error));
                }
                let choice = &answer["choices"][0];
                let content = &choice["message"]["content"];
                let text = match content {
                    Value::Null => String::new(),
                    Value::String(text) => text.clone(),
                    _ => {
                        let error = self.redact(&format!("{what}: unreadable response"));
                        return Err(unreadable(attempt, error));
                    }
                };
                (text, choice["finish_reason"] == "length")
            }
        };
        attempt.raw = Some(text.clone());
        attempt.cut_off = cut_off;
        ledger.ended = Some(now(cx));
        Ok(text)
    }

    /// Asks once, and once more with the reason if the answer cannot be
    /// read. Returns the read answer or the failure, and the ledger.
    pub async fn ask<T>(
        &self,
        cx: &Cx,
        system: &str,
        user: &str,
        max_tokens: u32,
        read: impl Fn(&str) -> Result<T, Unreadable>,
        rejected: impl Fn(&Unreadable),
    ) -> (Result<Answer<T>, Failure>, Ledger) {
        let mut ledger = Ledger::new();
        let mut user = user.to_owned();
        for ask in 1..=2 {
            ledger.ask = ask;
            let text = match self
                .complete(cx, system, &user, max_tokens, &mut ledger)
                .await
            {
                Ok(text) => text,
                Err(failure) => {
                    eprintln!("Page writer failed: {}", self.redact(&failure.error));
                    return (Err(failure), ledger);
                }
            };
            let read = if ledger
                .attempts
                .last()
                .is_some_and(|attempt| attempt.cut_off)
            {
                Err(Unreadable::Incomplete)
            } else {
                read(&text)
            };
            ledger.ended = Some(now(cx));
            match read {
                Ok(fields) => return (Ok(Answer { fields, raw: text }), ledger),
                Err(rejection) => {
                    rejected(&rejection);
                    let reason = rejection.to_string();
                    let last = ledger.attempts.last_mut().expect("an attempt");
                    last.outcome = AttemptOutcome::Unreadable;
                    last.error = Some(reason.clone());
                    let retry = ask < 2
                        && self.live.as_ref().is_none_or(|calls| {
                            calls
                                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                    (n < super::GENERATION_BUDGET).then_some(n + 1)
                                })
                                .is_ok()
                        });
                    if ask == 2 || !retry {
                        eprintln!(
                            "Page writer failed: {}{}",
                            self.redact(&reason),
                            if ledger.attempts.last().is_some_and(|a| a.cut_off) {
                                " (output limit)"
                            } else {
                                ""
                            }
                        );
                        return (
                            Err(Failure {
                                error: reason,
                                rejection: Some(rejection),
                            }),
                            ledger,
                        );
                    }
                    user = format!(
                        "{user}\n\nPrevious answer:\n{text}\n\nThe previous answer could not be read: {reason}\nRewrite the full answer in the requested format. Preserve its legitimate facts and links, and fix the named issue. Finish the entire answer within {max_tokens} output tokens."
                    );
                }
            }
        }
        unreachable!("the second ask returns")
    }
}

/// Keeps the model name and the reported tokens and cost of `answer`.
/// Missing, negative or non-integer amounts stay unknown.
fn usage(answer: &Value, attempt: &mut Attempt) {
    if let Some(model) = answer["model"].as_str().filter(|m| !m.is_empty()) {
        attempt.model = model.into();
    }
    let usage = &answer["usage"];
    if !usage.is_object() {
        return;
    }
    let count = |name: &str, alias: &str| {
        let value = usage.get(name).or_else(|| usage.get(alias))?;
        value.as_u64().filter(|_| !value.is_boolean())
    };
    attempt.input_tokens = count("input_tokens", "prompt_tokens");
    attempt.output_tokens = count("output_tokens", "completion_tokens");
    attempt.cost = usage["cost"]
        .as_f64()
        .filter(|c| c.is_finite() && *c >= 0.0);
}

/// A writer event carries its actual provider as well as the transport attempt.
pub(crate) type WriterObserver = dyn Fn(&Cx, fictionet_extras::models::Provider, &fictionet_extras::models::UpstreamEvent)
    + Send
    + Sync;
impl super::Pages {
    pub(crate) fn observe_writer(&self, observer: Arc<WriterObserver>) {
        if let Some(super::Maker::Model(model)) = &self.maker {
            let provider = model.provider.into();
            model.observe_upstream(Arc::new(move |cx, event| observer(cx, provider, event)));
        }
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::observation::{EgressPhase, EgressPurpose, SearchObs};
    use std::io::{BufRead, Read, Write};

    #[test]
    fn reasks_share_one_generation_deadline() {
        struct Slow;
        impl Transport for Slow {
            fn post<'a>(
                &'a self,
                cx: &'a Cx,
                _: Vec<(&'static str, String)>,
                _: Vec<u8>,
            ) -> fictionet_extras::models::Post<'a> {
                Box::pin(async move {
                    cx.sleep(Duration::from_secs(70))
                        .await
                        .map_err(|_| "cancelled".to_owned())?;
                    Ok((200, br#"{"content":[{"type":"text","text":"unreadable"}],"stop_reason":"end_turn"}"#.to_vec()))
                })
            }
        }
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(9),
            |cx| async move {
                let model = Model::new(
                    Provider::Anthropic,
                    "",
                    "",
                    Key::new("test key", Some("private-test".into()))
                        .map_err(fictionet::Error::msg)?,
                    Arc::new(Slow),
                )
                .live(Arc::new(AtomicUsize::new(0)));
                let (answer, ledger) = model
                    .ask(
                        &cx,
                        "Write a page.",
                        "About stars.",
                        200,
                        |_| Err::<(), _>(Unreadable::Format("try again".into())),
                        |_| {},
                    )
                    .await;
                assert!(answer.is_err());
                assert_eq!(ledger.attempts.len(), 2);
                assert_eq!(ledger.usage().gen_ms, TIMEOUT.as_millis() as u64);
                assert_eq!(cx.now().since_start(), TIMEOUT);
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn subscription_writer_uses_host_auth_and_records_its_upstream_attempt() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = std::io::BufReader::new(&mut socket);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                headers.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let headers = headers.to_ascii_lowercase();
            assert!(headers.contains("authorization: bearer sk-ant-oat01-private-test"));
            assert!(headers.contains("anthropic-beta: oauth-2025-04-20"));
            assert!(!headers.contains("x-api-key:"));
            let length: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                body["system"][0]["text"],
                "You are Claude Code, Anthropic's official CLI for Claude."
            );
            assert_eq!(body["system"][1]["text"], "Write a page.");
            assert_eq!(body["model"], "claude-sonnet-5-5");
            assert_eq!(body["thinking"]["type"], "between_tools");
            assert_eq!(body["output_config"]["effort"], "low");
            assert!(body.get("temperature").is_none());
            let response = r#"{"content":[{"type":"text","text":"A written page."}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":4}}"#;
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
        });
        fictionet::block_on(fictionet::run(fictionet::Seed::from_u64(6), |cx| async move {
            let key = Key::claude_token(fictionet_extras::models::Secret::new("Claude token", "sk-ant-oat01-private-test".into())?).map_err(fictionet::Error::msg)?;
            let mut model = Model::claude_token(key);
            model.transport = fictionet_extras::models::Authenticated::new(model.key.clone(), Arc::new(fictionet_extras::models::Https::at(&cx, format!("http://{address}").parse()?, "/v1/messages")?));
            let pages = super::super::Pages::open(super::super::Seed::builtin("web")?, super::super::Store::memory(), Some(super::super::Maker::Model(model)), 0);
            let (sender, mut observations) = tokio::sync::mpsc::channel(crate::observation::OBSERVATION_CAPACITY);
            pages.observe(sender);
            let Some(super::super::Maker::Model(model)) = &pages.maker else { panic!("model writer") };
            let text = model.complete(&cx, "Write a page.", "About stars.", 200, &mut Ledger::new()).await.map_err(|e| fictionet::Error::msg(e.error))?;
            assert_eq!(text, "A written page.");
            let first = observations.try_recv().unwrap();
            let last = observations.try_recv().unwrap();
            let SearchObs::Egress { attempt, purpose: EgressPurpose::PageWriter, phase: EgressPhase::Attempt, .. } = first.fact else { panic!("writer attempt") };
            assert!(matches!(last.fact, SearchObs::Egress { attempt: id, purpose: EgressPurpose::PageWriter, phase: EgressPhase::Response, status: Some(200), .. } if id == attempt));
            assert!(!serde_json::to_string(&[first, last])?.contains("private-test"));
            assert!(observations.try_recv().is_err());
            Ok(())
        })).unwrap();
        upstream.join().unwrap();
    }
}
