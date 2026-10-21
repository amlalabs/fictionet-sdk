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

/// One HTTP attempt. Times are seconds on the run's clock.
#[derive(Clone, Debug, Serialize)]
pub struct Attempt {
    pub ask: u32,
    pub attempt: u32,
    pub started: f64,
    pub ended: f64,
    pub outcome: String,
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
    /// One offline generation that took `ms`.
    pub fn stub(ms: u64) -> Self {
        Self {
            model: "stub".into(),
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
            call_ms: (last.outcome == "ok").then(|| last.ms()),
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
    /// The reasoning effort sent to OpenRouter, or empty for the model's own.
    pub reasoning: String,
    key: Key,
    transport: Arc<dyn Transport>,
    live: Option<Arc<AtomicUsize>>,
}

/// A read answer, with the raw text the model gave.
pub struct Answer<T> {
    pub fields: T,
    pub raw: String,
}

struct OpenRouter;

impl Transport for OpenRouter {
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> fictionet_extras::models::Post<'a> {
        Box::pin(async move {
            fictionet_extras::models::Https::new(cx, fictionet_extras::models::Provider::OpenRouter)
                .map_err(|e| e.to_string())?
                .post(cx, headers, body)
                .await
        })
    }
}

impl Model {
    /// The default page writer, using the existing OpenRouter credential.
    pub fn openrouter() -> Result<Self, String> {
        Ok(Self::new(
            Provider::OpenRouter,
            "",
            "",
            Key::from_env(fictionet_extras::models::Provider::OpenRouter)?,
            Arc::new(OpenRouter),
        ))
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
            key,
            transport,
            live: None,
        }
    }

    /// A shared call cap and nine-second budget for an interactive request.
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
            Provider::Anthropic => (
                vec![
                    self.key.header(self.provider.into()),
                    ("anthropic-version", "2023-06-01".into()),
                    ("content-type", "application/json".into()),
                ],
                json!({
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "temperature": 1.0,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                }),
            ),
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
        let timeout = if self.live.is_some() {
            let elapsed = ledger.attempts.first().map_or(0.0, |a| now(cx) - a.started);
            Duration::from_secs(9).saturating_sub(Duration::from_secs_f64(elapsed))
        } else {
            TIMEOUT
        };
        for index in 1..=attempts {
            let mut attempt = Attempt {
                ask: ledger.ask,
                attempt: index,
                started: now(cx),
                ended: 0.0,
                outcome: "transport".into(),
                model: self.model.clone(),
                input_tokens: None,
                output_tokens: None,
                cost: None,
                raw: None,
                cut_off: false,
                backoff_ms: 0,
                error: None,
            };
            let deadline = cx.now() + timeout;
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
                            attempt.outcome = "ok".into();
                            ledger.attempts.push(attempt);
                            ledger.ended = Some(now(cx));
                            return Ok(answer);
                        }
                        Ok(_) => {
                            attempt.outcome = "unreadable".into();
                            failure = "the model's response is not a JSON object".into();
                        }
                        Err(error) => {
                            attempt.outcome = "unreadable".into();
                            failure = format!("the model's response is not JSON: {error}");
                        }
                    }
                }
                Ok(Ok((status, reply))) => {
                    attempt.outcome = format!("http {status}");
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
            attempt.outcome = "unreadable".into();
            attempt.error = Some(error.clone());
            Failure { error }
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
                Err(failure) => return (Err(failure), ledger),
            };
            let read = read(&text);
            ledger.ended = Some(now(cx));
            match read {
                Ok(fields) => return (Ok(Answer { fields, raw: text }), ledger),
                Err(Unreadable(reason)) => {
                    let last = ledger.attempts.last_mut().expect("an attempt");
                    last.outcome = "unreadable".into();
                    last.error = Some(reason.clone());
                    let retry = ask < 2
                        && self.live.as_ref().is_none_or(|calls| {
                            super::gives_away(&text).is_some()
                                && now(cx) - ledger.attempts[0].started <= 5.0
                                && calls
                                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                        (n < super::GENERATION_BUDGET).then_some(n + 1)
                                    })
                                    .is_ok()
                        });
                    if ask == 2 || !retry {
                        return (Err(Failure { error: reason }), ledger);
                    }
                    user.push_str(&format!(
                        "\n\nThe previous answer could not be read: {reason}\nAnswer again in the requested format."
                    ));
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
