//! Model calls: Anthropic's Messages API and OpenRouter's OpenAI-compatible
//! chat completions, over the SDK's own HTTP client.
//!
//! A [`Model`] answers one conversation at a time with JSON that follows a
//! schema. Rate limits and overloaded or failing servers are asked again
//! after a growing pause until an answer arrives. An answer that cannot be
//! read is followed by a message saying why, and the model answers again.
//!
//! The key is sent in the request's header and nowhere else, and is
//! replaced by the variable's name in every error message.

use std::sync::Arc;
use std::time::Duration;

use fictionet::Cx;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use fictionet_extras::models::{Key, Transport};

/// The synchronous Messages API maximum for current Claude models.
const OUTPUT_CEILING: u32 = 128_000;

/// Answers worth asking again: rate limits and overloaded or failing servers.
const RETRY: [u16; 7] = [408, 429, 500, 502, 503, 504, 529];

/// A model API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Anthropic,
    OpenRouter,
}

/// How much a question needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Care {
    /// The fastest model.
    Fast,
    /// A stronger model that answers without thinking first: still quick,
    /// and it follows long instructions to the letter.
    Exact,
    /// The stronger model, thinking first: for a question asked once and
    /// in the background.
    Careful,
}

impl Provider {
    /// The model used when none is named.
    pub(in crate::pages) fn default_model(self) -> &'static str {
        self.model(Care::Fast)
    }

    fn model(self, care: Care) -> &'static str {
        match (self, care) {
            (Self::Anthropic, Care::Fast) => "claude-haiku-5-5",
            (Self::Anthropic, Care::Exact | Care::Careful) => "claude-sonnet-5-5",
            (Self::OpenRouter, Care::Fast) => "anthropic/claude-haiku-5.5",
            (Self::OpenRouter, Care::Exact | Care::Careful) => "anthropic/claude-sonnet-5.5",
        }
    }
    pub(in crate::pages) fn label(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic",
            Self::OpenRouter => "OpenRouter",
        }
    }
}

impl From<Provider> for fictionet_extras::models::Provider {
    fn from(provider: Provider) -> Self {
        match provider {
            Provider::Anthropic => Self::Anthropic,
            Provider::OpenRouter => Self::OpenRouter,
        }
    }
}

/// Who said a turn of a conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Role {
    User,
    Assistant,
}

/// One turn of a conversation.
#[derive(Clone, Debug, Serialize)]
pub(super) struct Turn {
    pub role: Role,
    pub content: String,
}

/// A conversation with the model: what the world asked, what the model
/// answered, and what the world said about each answer.
#[derive(Clone, Debug, Default)]
pub(super) struct Conversation {
    turns: Vec<Turn>,
}

impl Conversation {
    pub(super) fn new(question: String) -> Self {
        Self {
            turns: vec![Turn {
                role: Role::User,
                content: question,
            }],
        }
    }

    /// Tells the model about its last answer.
    pub(super) fn reply(&mut self, content: String) {
        self.turns.push(Turn {
            role: Role::User,
            content,
        });
    }

    fn answered(&mut self, content: String) {
        self.turns.push(Turn {
            role: Role::Assistant,
            content,
        });
    }
}

/// A model and how to reach it.
pub struct Model {
    provider: Provider,
    model: String,
    transport: fictionet_extras::models::Authenticated,
}

mod transport;
use transport::ProviderTransport;

impl Model {
    /// A model on OpenRouter, with the host's `OPENROUTER_API_KEY`.
    pub fn openrouter() -> Result<Self, String> {
        Ok(Self::new(
            Provider::OpenRouter,
            Key::from_env(fictionet_extras::models::Provider::OpenRouter)?,
        ))
    }

    /// A model on Anthropic's API, with the host's `ANTHROPIC_API_KEY`.
    pub fn anthropic() -> Result<Self, String> {
        Ok(Self::new(
            Provider::Anthropic,
            Key::from_env(fictionet_extras::models::Provider::Anthropic)?,
        ))
    }

    /// Uses the same host-held Claude subscription credential as the guest gateway.
    pub fn claude_token(key: Key) -> Self {
        Self::new(Provider::Anthropic, key)
    }

    fn new(provider: Provider, key: Key) -> Self {
        Self {
            provider,
            model: provider.default_model().into(),
            transport: fictionet_extras::models::Authenticated::new(
                provider.into(),
                key,
                Arc::new(ProviderTransport::new(provider)),
            ),
        }
    }

    /// The provider whose API answers.
    pub fn provider(&self) -> Provider {
        self.provider
    }

    /// Installs observation on the reusable provider transport.
    pub fn observe_upstream(&self, observer: Arc<fictionet_extras::models::UpstreamObserver>) {
        self.transport.observe_upstream(observer);
    }

    /// `text` without the key.
    pub fn redact(&self, text: &str) -> String {
        self.transport.redact(text)
    }

    fn request(
        &self,
        care: Care,
        system: &str,
        conversation: &Conversation,
        schema: &Value,
    ) -> Value {
        let model = match care {
            Care::Fast => self.model.as_str(),
            Care::Exact | Care::Careful => self.provider.model(care),
        };
        match self.provider {
            Provider::Anthropic => {
                let system = if self.transport.is_claude_token() {
                    json!([
                        {"type":"text", "text":"You are Claude Code, Anthropic's official CLI for Claude."},
                        {"type":"text", "text":system, "cache_control":{"type":"ephemeral"}}
                    ])
                } else {
                    json!(system)
                };
                let thinking = match care {
                    Care::Fast => json!({"type": "disabled"}),
                    // Sonnet 5.5 turns thinking off this way.
                    Care::Exact => json!({"type": "between_tools"}),
                    Care::Careful => json!({"type": "adaptive"}),
                };
                json!({
                    "model": model,
                    "max_tokens": OUTPUT_CEILING,
                    "thinking": thinking,
                    "system": system,
                    "messages": conversation.turns,
                    "output_config": {"format": {"type": "json_schema", "schema": schema}},
                })
            }
            Provider::OpenRouter => {
                let mut messages = vec![json!({"role": "system", "content": system})];
                messages.extend(conversation.turns.iter().map(|turn| json!(turn)));
                json!({
                    "model": model,
                    "max_tokens": OUTPUT_CEILING,
                    "messages": messages,
                    "reasoning": {"enabled": care == Care::Careful},
                    // The fastest provider that serves the model, not the cheapest.
                    "provider": {"sort": "throughput"},
                    "response_format": {"type": "json_schema", "json_schema": {"name": "answer", "strict": true, "schema": schema}},
                })
            }
        }
    }

    /// Asks the model `care` calls for until it gives JSON of type `T`
    /// that follows `schema`, and adds its answer to `conversation`.
    pub(super) async fn json<T: DeserializeOwned>(
        &self,
        cx: &Cx,
        care: Care,
        system: &str,
        conversation: &mut Conversation,
        schema: &Value,
    ) -> Result<T, String> {
        loop {
            let text = self
                .complete(cx, &self.request(care, system, conversation, schema))
                .await?;
            conversation.answered(text.clone());
            match serde_json::from_str::<T>(&text) {
                Ok(answer) => return Ok(answer),
                Err(error) => conversation.reply(format!(
                    "That answer could not be read as the requested JSON: {error}. Answer again with JSON only."
                )),
            }
        }
    }

    /// POSTs one request, asking again what is worth asking again until it
    /// is answered, and returns the answer's text.
    async fn complete(&self, cx: &Cx, body: &Value) -> Result<String, String> {
        let what = format!("{} {}", self.provider.label(), self.model);
        let data = serde_json::to_vec(body).expect("a JSON value");
        for attempt in 1u64.. {
            let failure = match cx.race(None, self.transport.post(cx, data.clone())).await {
                Ok(Ok((status, reply))) if (200..300).contains(&status) => {
                    match serde_json::from_slice::<Value>(&reply) {
                        Ok(answer) => {
                            let completion = fictionet_extras::models::Completion::read(
                                self.provider.into(),
                                &answer,
                            )
                            .map_err(|reason| self.redact(&format!("{what}: {reason}")))?;
                            return Ok(self.redact(&completion.text));
                        }
                        Err(error) => format!("the response is not JSON: {error}"),
                    }
                }
                Ok(Ok((status, reply))) => {
                    let detail = self.redact(&String::from_utf8_lossy(&reply));
                    if !RETRY.contains(&status) {
                        return Err(format!("{what} failed: HTTP {status}: {detail}"));
                    }
                    format!("HTTP {status}: {detail}")
                }
                Ok(Err(error)) => self.redact(&error),
                Err(_) => return Err(format!("{what} failed: the world stopped")),
            };
            eprintln!("{what} will be asked again: {failure}");
            if cx
                .sleep(Duration::from_millis(1500 * attempt))
                .await
                .is_err()
            {
                return Err(format!("{what} failed: the world stopped"));
            }
        }
        unreachable!("the request loop returns its answer")
    }
}
