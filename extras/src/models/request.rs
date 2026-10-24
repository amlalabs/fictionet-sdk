//! Decoded provider input containers. Unknown fields and remote references fail closed.
//!
//! Inert sampling options and client function arguments are opaque. Provider content
//! is decoded recursively, including nested tool results and inline documents.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub(super) enum Admitted {
    Messages(Box<Messages>),
    Responses(Box<Responses>),
    Chat(Box<Chat>),
    Gemini(Box<Gemini>),
}

macro_rules! protocol {
    ($name:ident { $($(#[$attr:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        pub(super) struct $name {
            $($(#[$attr])* #[serde(skip_serializing_if = "Option::is_none")] pub(super) $field: Option<$ty>,)*
        }
    };
}
protocol!(Messages {
    model: ModelName, messages: Vec<Message>, system: Content, tools: Vec<Tool>,
    max_tokens: u64, temperature: f64, top_p: f64, top_k: u64, stream: bool,
    stop_sequences: Vec<String>, tool_choice: Value, metadata: Value,
    diagnostics: Diagnostics, safeguards: Vec<Safeguard>, cache_control: Value,
    thinking: Thinking, output_config: OutputConfig, context_management: Value,
    service_tier: String,
});
protocol!(Responses {
    model: ModelName, input: Content, instructions: String, tools: Vec<Tool>,
    max_output_tokens: u64, max_tool_calls: u64, temperature: f64, top_p: f64,
    stream: bool, stream_options: Value, tool_choice: Value, parallel_tool_calls: bool,
    metadata: Value, user: String, safety_identifier: String, prompt_cache_key: String,
    prompt_cache_retention: String, store: bool, previous_response_id: String,
    conversation: String, include: Vec<String>, reasoning: Reasoning, text: Value,
    service_tier: String, truncation: String, context_management: Value,
    client_metadata: Value,
});
protocol!(Chat {
    model: ModelName, messages: Vec<Message>, tools: Vec<Tool>, functions: Vec<Function>,
    max_tokens: u64, max_completion_tokens: u64, temperature: f64, top_p: f64,
    stream: bool, stream_options: Value, stop: Stop, tool_choice: Value,
    function_call: Value, parallel_tool_calls: bool, metadata: Value, user: String,
    safety_identifier: String, prompt_cache_key: String, prompt_cache_retention: String,
    store: bool, reasoning: Reasoning, reasoning_effort: String, response_format: Value,
    service_tier: String, frequency_penalty: f64, presence_penalty: f64,
    logit_bias: std::collections::HashMap<String, f64>, logprobs: bool, top_logprobs: u64,
    seed: i64, n: u64, modalities: Vec<String>, audio: Value, prediction: Prediction,
    provider: Value, usage: Value, transforms: Vec<String>, models: Vec<ModelName>, route: String,
});
protocol!(Gemini {
    model: ModelName, contents: Content,
    #[serde(rename = "systemInstruction", alias = "system_instruction")] system_instruction: Content,
    tools: Vec<Tool>,
    #[serde(rename = "generationConfig", alias = "generation_config")] generation_config: GenerationConfig,
    #[serde(rename = "safetySettings", alias = "safety_settings")] safety_settings: Value,
    #[serde(rename = "toolConfig", alias = "tool_config")] tool_config: Value,
});

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Stop {
    One(String),
    Many(Vec<String>),
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Thinking {
    Enabled { budget_tokens: u64 },
    Disabled,
    Adaptive,
    BetweenTools,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reasoning {
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exclude: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u64>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_k: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_json_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking_config: Option<GeminiThinking>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GeminiThinking {
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking_budget: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    include_thoughts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking_level: Option<String>,
}

impl Admitted {
    pub(super) fn model(&self) -> Option<&str> {
        let model = match self {
            Self::Messages(r) => &r.model,
            Self::Responses(r) => &r.model,
            Self::Chat(r) => &r.model,
            Self::Gemini(r) => &r.model,
        };
        model.as_ref().map(|name| name.0.as_str())
    }

    pub(super) fn decode(
        provider: super::Provider,
        path: &str,
        value: &Value,
        world: bool,
    ) -> Option<Self> {
        use super::Provider;
        let admitted = if path.ends_with("/messages") || path.ends_with("/messages/count_tokens") {
            Self::Messages(serde_json::from_value(value.clone()).ok()?)
        } else if path.ends_with("/responses") {
            Self::Responses(serde_json::from_value(value.clone()).ok()?)
        } else if provider == Provider::Gemini {
            Self::Gemini(serde_json::from_value(value.clone()).ok()?)
        } else if path.ends_with("/chat/completions") {
            Self::Chat(serde_json::from_value(value.clone()).ok()?)
        } else {
            // Operational GET endpoints carry no provider content.
            return value
                .as_object()
                .filter(|object| object.is_empty())
                .map(|_| Self::Messages(serde_json::from_value(value.clone()).unwrap()));
        };
        let valid = match &admitted {
            Self::Messages(r) => {
                r.messages.as_ref().is_none_or(|messages| {
                    messages
                        .iter()
                        .all(|message| message.allowed(Wire::Messages))
                }) && r
                    .system
                    .as_ref()
                    .is_none_or(|content| content.allowed(Wire::Messages))
            }
            Self::Responses(r) => r
                .input
                .as_ref()
                .is_none_or(|content| content.allowed(Wire::Responses)),
            Self::Chat(r) => r
                .messages
                .as_ref()
                .is_none_or(|messages| messages.iter().all(|message| message.allowed(Wire::Chat))),
            Self::Gemini(r) => {
                r.contents
                    .as_ref()
                    .is_none_or(|content| content.allowed(Wire::Gemini))
                    && r.system_instruction
                        .as_ref()
                        .is_none_or(|content| content.allowed(Wire::Gemini))
            }
        };
        if !valid {
            return None;
        }
        let tools = match &admitted {
            Self::Messages(r) => &r.tools,
            Self::Responses(r) => &r.tools,
            Self::Chat(r) => &r.tools,
            Self::Gemini(r) => &r.tools,
        };
        if let Self::Chat(chat) = &admitted
            && provider != Provider::OpenRouter
            && (chat.provider.is_some()
                || chat.usage.is_some()
                || chat.transforms.is_some()
                || chat.models.is_some()
                || chat.route.is_some()
                || chat.reasoning.is_some())
        {
            return None;
        }
        tools
            .as_ref()
            .is_none_or(|tools| tools.iter().all(|tool| tool.allowed(provider, path, world)))
            .then_some(admitted)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Function {
    pub(super) name: String,
    pub(super) parameters: serde_json::Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strict: Option<bool>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Tool {
    Tagged(TaggedTool),
    Client(ClientTool),
    Gemini(GeminiTool),
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClientTool {
    pub(super) name: String,
    pub(super) input_schema: serde_json::Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strict: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    defer_loading: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_examples: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_callers: Option<Vec<String>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GeminiTool {
    #[serde(rename = "functionDeclarations", alias = "function_declarations")]
    functions: Vec<Value>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum TaggedTool {
    Function {
        #[serde(skip_serializing_if = "Option::is_none")]
        function: Option<Function>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameters: Option<serde_json::Map<String, Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        strict: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        defer_loading: Option<bool>,
    },
    Custom {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_schema: Option<serde_json::Map<String, Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        strict: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        defer_loading: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        input_examples: Option<Vec<Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        allowed_callers: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        format: Option<Value>,
    },
    Namespace {
        name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        tools: Vec<Tool>,
    },
    #[serde(rename = "web_search_20250305")]
    WebSearch20250305(WebSettings),
    #[serde(rename = "web_search_20260209")]
    WebSearch20260209(WebSettings),
    #[serde(rename = "web_fetch_20250910")]
    WebFetch20250910(WebSettings),
    #[serde(rename = "web_fetch_20260209")]
    WebFetch20260209(WebSettings),
    WebSearch(WebSettings),
    WebSearchPreview(WebSettings),
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WebSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) max_uses: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_location: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) filters: Option<super::tools::Domains>,
    #[serde(skip_serializing_if = "Option::is_none")]
    search_context_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_web_access: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) citations: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) max_content_tokens: Option<u64>,
}
impl Tool {
    fn allowed(&self, provider: super::Provider, path: &str, world: bool) -> bool {
        use super::Provider;
        match self {
            Self::Client(_) => {
                matches!(provider, Provider::Anthropic | Provider::OpenRouter)
                    && (path.ends_with("/messages") || path.ends_with("/messages/count_tokens"))
            }
            Self::Gemini(_) => provider == Provider::Gemini,
            Self::Tagged(TaggedTool::Namespace { tools, .. }) => {
                tools.iter().all(|tool| tool.allowed(provider, path, false))
            }
            Self::Tagged(TaggedTool::Function { function, name, .. }) => {
                if path.ends_with("/chat/completions") {
                    function.is_some() && name.is_none()
                } else {
                    path.ends_with("/responses") && function.is_none() && name.is_some()
                }
            }
            Self::Tagged(TaggedTool::Custom {
                input_schema,
                format,
                ..
            }) => {
                if path.ends_with("/messages") || path.ends_with("/messages/count_tokens") {
                    matches!(provider, Provider::Anthropic | Provider::OpenRouter)
                        && input_schema.is_some()
                        && format.is_none()
                } else {
                    path.ends_with("/responses") && input_schema.is_none()
                }
            }
            Self::Tagged(
                TaggedTool::WebSearch20250305(_)
                | TaggedTool::WebSearch20260209(_)
                | TaggedTool::WebFetch20250910(_)
                | TaggedTool::WebFetch20260209(_),
            ) => {
                world
                    && provider == Provider::Anthropic
                    && (path.ends_with("/messages") || path.ends_with("/messages/count_tokens"))
            }
            Self::Tagged(TaggedTool::WebSearch(_) | TaggedTool::WebSearchPreview(_)) => {
                world
                    && matches!(provider, Provider::OpenAi | Provider::ChatGpt)
                    && path.ends_with("/responses")
            }
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prediction {
    #[serde(rename = "type")]
    kind: PredictionKind,
    content: Content,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum PredictionKind {
    Content,
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub(super) enum Content {
    Text(String),
    Blocks(Vec<Content>),
    Block(Box<Block>),
    Empty(()),
}

impl<'de> Deserialize<'de> for Content {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(text) => Ok(Self::Text(text)),
            Value::Array(items) => items
                .into_iter()
                .map(serde_json::from_value)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::Blocks)
                .map_err(serde::de::Error::custom),
            Value::Object(_) => serde_json::from_value(value)
                .map(Self::Block)
                .map_err(serde::de::Error::custom),
            Value::Null => Ok(Self::Empty(())),
            _ => Err(serde::de::Error::custom(
                "content must be text, blocks or a message",
            )),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Block {
    Typed(TypedBlock),
    Message(Message),
    Parts(Parts),
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Message {
    pub(super) role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) content: Option<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_config: Option<OutputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_call: Option<Value>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Parts {
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parts: Option<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(rename = "inlineData", alias = "inline_data")]
    #[serde(skip_serializing_if = "Option::is_none")]
    inline_data: Option<InlineBytes>,
    #[serde(rename = "functionCall")]
    #[serde(skip_serializing_if = "Option::is_none")]
    function_call: Option<FunctionCall>,
    #[serde(rename = "functionResponse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    function_response: Option<FunctionResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thought: Option<bool>,
    #[serde(rename = "thoughtSignature")]
    #[serde(skip_serializing_if = "Option::is_none")]
    thought_signature: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum TypedBlock {
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        citations: Option<Value>,
    },
    InputText {
        text: String,
    },
    OutputText {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        annotations: Option<Value>,
    },
    Refusal {
        refusal: String,
    },
    Image {
        source: Source,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<Value>,
    },
    ImageUrl {
        image_url: Image,
    },
    InputImage {
        image_url: Image,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    InputFile {
        file_data: InlineData,
        #[serde(skip_serializing_if = "Option::is_none")]
        filename: Option<String>,
    },
    Document {
        source: Source,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        citations: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<Value>,
    },
    ToolUse {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        name: String,
        input: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        caller: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<Value>,
    },
    ToolResult {
        tool_use_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        content: Option<Content>,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<Value>,
    },
    ToolReference {
        tool_name: String,
    },
    ServerToolUse {
        id: String,
        name: String,
        input: Value,
    },
    WebSearchResult {
        url: String,
        title: String,
        encrypted_content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        page_age: Option<String>,
    },
    WebSearchToolResultError {
        error_code: String,
    },
    WebFetchResult {
        url: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        retrieved_at: Option<String>,
        content: Content,
    },
    WebFetchToolResultError {
        error_code: String,
    },
    WebSearchToolResult {
        tool_use_id: String,
        content: Content,
    },
    WebFetchToolResult {
        tool_use_id: String,
        content: Content,
    },
    Thinking {
        thinking: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    RedactedThinking {
        data: String,
    },
    Message {
        role: Role,
        content: Content,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        phase: Option<String>,
    },
    FunctionCall {
        name: String,
        arguments: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        call_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    FunctionCallOutput {
        call_id: String,
        output: Content,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    CustomToolCall {
        name: String,
        input: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        call_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    CustomToolCallOutput {
        call_id: String,
        output: Content,
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    Reasoning {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        summary: Option<Content>,
        #[serde(skip_serializing_if = "Option::is_none")]
        content: Option<Content>,
        #[serde(skip_serializing_if = "Option::is_none")]
        encrypted_content: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    SummaryText {
        text: String,
    },
    WebSearchCall {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        encrypted_content: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<String>,
        action: Value,
    },
    InputAudio {
        input_audio: InputAudio,
    },
    Audio {
        audio: Value,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Source {
    Base64 {
        media_type: String,
        data: String,
    },
    Text {
        data: String,
        media_type: Option<String>,
    },
    Content {
        content: Content,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Image {
    Data(InlineData),
    Object(ImageObject),
}

#[derive(Clone)]
pub(super) struct InlineData(String);
impl<'de> Deserialize<'de> for InlineData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = String::deserialize(deserializer)?;
        if data.starts_with("data:")
            && data
                .split_once(',')
                .is_some_and(|(head, _)| head.ends_with(";base64"))
        {
            Ok(Self(data))
        } else {
            Err(serde::de::Error::custom(
                "content must be inline base64 data",
            ))
        }
    }
}

#[derive(Clone)]
pub(super) struct ModelName(String);
impl<'de> Deserialize<'de> for ModelName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        if name.split(':').skip(1).any(|variant| variant == "online") || name.contains("-search-") {
            Err(serde::de::Error::custom(
                "model requires external retrieval",
            ))
        } else {
            Ok(Self(name))
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageObject {
    url: InlineData,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InlineBytes {
    #[serde(rename = "mimeType", alias = "mime_type")]
    mime_type: String,
    data: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InputAudio {
    data: String,
    format: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FunctionCall {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    args: Value,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FunctionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    response: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    parts: Option<Content>,
    #[serde(rename = "willContinue", alias = "will_continue")]
    #[serde(skip_serializing_if = "Option::is_none")]
    will_continue: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scheduling: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OutputConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<Value>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Diagnostics {
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_message_id: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Safeguard {
    DangerousToolUse { classifier_context: Value },
}

impl Serialize for InlineData {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl Serialize for ModelName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Role {
    System,
    Developer,
    User,
    Assistant,
    Tool,
    Model,
    Function,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WebTool {
    Search,
    Fetch,
}
impl WebTool {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Search => "web_search",
            Self::Fetch => "web_fetch",
        }
    }
}
impl Tool {
    pub(super) fn web(&self) -> Option<(WebTool, &WebSettings)> {
        match self {
            Self::Tagged(
                TaggedTool::WebSearch20250305(settings)
                | TaggedTool::WebSearch20260209(settings)
                | TaggedTool::WebSearch(settings)
                | TaggedTool::WebSearchPreview(settings),
            ) => Some((WebTool::Search, settings)),
            Self::Tagged(
                TaggedTool::WebFetch20250910(settings) | TaggedTool::WebFetch20260209(settings),
            ) => Some((WebTool::Fetch, settings)),
            _ => None,
        }
    }
    pub(super) fn function(name: &str, description: &str, parameters: Value) -> Self {
        Self::Client(ClientTool {
            name: name.into(),
            description: Some(description.into()),
            input_schema: parameters.as_object().expect("function schema").clone(),
            cache_control: None,
            strict: None,
            defer_loading: None,
            input_examples: None,
            allowed_callers: None,
        })
    }
}
impl Message {
    pub(super) fn new(role: Role, content: Content) -> Self {
        Self {
            role,
            content: Some(content),
            output_config: None,
            name: None,
            tool_calls: None,
            tool_call_id: None,
            function_call: None,
        }
    }
}
impl Content {
    pub(super) fn typed(block: TypedBlock) -> Self {
        Self::Block(Box::new(Block::Typed(block)))
    }
    pub(super) fn into_blocks(self) -> Vec<Content> {
        match self {
            Self::Blocks(blocks) => blocks,
            Self::Text(text) => vec![Self::typed(TypedBlock::Text {
                text,
                cache_control: None,
                citations: None,
            })],
            Self::Empty(()) => vec![],
            block => vec![block],
        }
    }
    pub(super) fn into_input(self) -> Vec<Content> {
        match self {
            Self::Text(text) => vec![Self::Block(Box::new(Block::Message(Message::new(
                Role::User,
                Self::Text(text),
            ))))],
            Self::Blocks(blocks) => blocks,
            Self::Empty(()) => vec![],
            block => vec![block],
        }
    }
    pub(super) fn has_server_history(&self) -> bool {
        match self {
            Self::Blocks(blocks) => blocks.iter().any(Self::has_server_history),
            Self::Block(block) => matches!(
                **block,
                Block::Typed(TypedBlock::ServerToolUse { .. } | TypedBlock::WebSearchCall { .. })
            ),
            _ => false,
        }
    }
}
impl Messages {
    pub(super) fn needs_web(&self) -> bool {
        self.tools
            .as_ref()
            .is_some_and(|tools| tools.iter().any(|tool| tool.web().is_some()))
            || self.messages.as_ref().is_some_and(|messages| {
                messages
                    .iter()
                    .filter_map(|message| message.content.as_ref())
                    .any(Content::has_server_history)
            })
    }
}
impl Responses {
    pub(super) fn needs_web(&self) -> bool {
        self.tools
            .as_ref()
            .is_some_and(|tools| tools.iter().any(|tool| tool.web().is_some()))
            || self.input.as_ref().is_some_and(Content::has_server_history)
    }
}

impl WebSettings {
    pub(super) fn domains(&self) -> super::tools::Domains {
        super::tools::Domains {
            allowed_domains: self.allowed_domains.clone(),
            blocked_domains: self.blocked_domains.clone(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Wire {
    Messages,
    Responses,
    Chat,
    Gemini,
}
impl Message {
    fn allowed(&self, wire: Wire) -> bool {
        let role = match wire {
            Wire::Messages => matches!(self.role, Role::System | Role::User | Role::Assistant),
            Wire::Chat => matches!(
                self.role,
                Role::System
                    | Role::Developer
                    | Role::User
                    | Role::Assistant
                    | Role::Tool
                    | Role::Function
            ),
            Wire::Responses => matches!(
                self.role,
                Role::System | Role::Developer | Role::User | Role::Assistant
            ),
            Wire::Gemini => false,
        };
        role && self
            .content
            .as_ref()
            .is_none_or(|content| content.allowed(wire))
            && (wire == Wire::Messages || self.output_config.is_none())
            && (wire == Wire::Chat
                || (self.name.is_none()
                    && self.tool_calls.is_none()
                    && self.tool_call_id.is_none()
                    && self.function_call.is_none()))
    }
}
impl Content {
    fn allowed(&self, wire: Wire) -> bool {
        match self {
            Self::Text(_) | Self::Empty(()) => true,
            Self::Blocks(items) => items.iter().all(|item| item.allowed(wire)),
            Self::Block(block) => match block.as_ref() {
                Block::Message(message) => message.allowed(wire),
                Block::Parts(parts) => {
                    wire == Wire::Gemini
                        && parts
                            .parts
                            .as_ref()
                            .is_none_or(|content| content.allowed(wire))
                }
                Block::Typed(block) => match block {
                    TypedBlock::Text { .. } => matches!(wire, Wire::Messages | Wire::Chat),
                    TypedBlock::Image { .. }
                    | TypedBlock::ToolUse { .. }
                    | TypedBlock::ToolReference { .. }
                    | TypedBlock::ServerToolUse { .. }
                    | TypedBlock::WebSearchResult { .. }
                    | TypedBlock::WebSearchToolResultError { .. }
                    | TypedBlock::WebFetchToolResultError { .. }
                    | TypedBlock::Thinking { .. }
                    | TypedBlock::RedactedThinking { .. } => wire == Wire::Messages,
                    TypedBlock::Document { source, .. } => {
                        wire == Wire::Messages && source.allowed(wire)
                    }
                    TypedBlock::ToolResult { content, .. } => {
                        wire == Wire::Messages
                            && content.as_ref().is_none_or(|content| content.allowed(wire))
                    }
                    TypedBlock::WebFetchResult { content, .. }
                    | TypedBlock::WebSearchToolResult { content, .. }
                    | TypedBlock::WebFetchToolResult { content, .. } => {
                        wire == Wire::Messages && content.allowed(wire)
                    }
                    TypedBlock::InputText { .. }
                    | TypedBlock::InputImage { .. }
                    | TypedBlock::InputFile { .. }
                    | TypedBlock::OutputText { .. }
                    | TypedBlock::Refusal { .. }
                    | TypedBlock::FunctionCall { .. }
                    | TypedBlock::CustomToolCall { .. }
                    | TypedBlock::SummaryText { .. }
                    | TypedBlock::WebSearchCall { .. } => wire == Wire::Responses,
                    TypedBlock::Message { role, content, .. } => {
                        wire == Wire::Responses
                            && matches!(
                                role,
                                Role::System | Role::Developer | Role::User | Role::Assistant
                            )
                            && content.allowed(wire)
                    }
                    TypedBlock::CustomToolCallOutput {
                        output: content, ..
                    }
                    | TypedBlock::FunctionCallOutput {
                        output: content, ..
                    } => wire == Wire::Responses && content.allowed(wire),
                    TypedBlock::Reasoning {
                        summary, content, ..
                    } => {
                        wire == Wire::Responses
                            && summary.as_ref().is_none_or(|content| content.allowed(wire))
                            && content.as_ref().is_none_or(|content| content.allowed(wire))
                    }
                    TypedBlock::ImageUrl { .. }
                    | TypedBlock::InputAudio { .. }
                    | TypedBlock::Audio { .. } => wire == Wire::Chat,
                },
            },
        }
    }
}
impl Source {
    fn allowed(&self, wire: Wire) -> bool {
        match self {
            Self::Content { content } => content.allowed(wire),
            Self::Base64 { .. } | Self::Text { .. } => true,
        }
    }
}
