//! Decoded provider input containers. Unknown fields and remote references fail closed.
//!
//! Inert sampling options and client function arguments are opaque. Provider content
//! is decoded recursively, including nested tool results and inline documents.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub(super) enum Admitted {
    Messages(Messages),
    Responses(Responses),
    Chat(Chat),
    Gemini(Gemini),
}

macro_rules! protocol {
    ($name:ident { $($(#[$attr:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        pub(super) struct $name {
            $($(#[$attr])* #[serde(skip_serializing_if = "Option::is_none")] pub(super) $field: Option<$ty>,)*
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) model: Option<ModelName>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) instructions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) max_tokens: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) max_output_tokens: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) max_completion_tokens: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) temperature: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) top_p: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) top_k: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) stream_options: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) stop: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) stop_sequences: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) tool_choice: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) function_call: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) parallel_tool_calls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            diagnostics: Option<Diagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
            safeguards: Option<Vec<Safeguard>>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) client_metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) safety_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) prompt_cache_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) prompt_cache_retention: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) cache_control: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) store: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) previous_response_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) conversation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) include: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) reasoning: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) reasoning_effort: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) thinking: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            output_config: Option<OutputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) text: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) response_format: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) service_tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) truncation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) context_management: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) frequency_penalty: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) presence_penalty: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) logit_bias: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) logprobs: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) top_logprobs: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) seed: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) n: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) modalities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) audio: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            prediction: Option<Prediction>,
    #[serde(rename = "generationConfig", alias = "generation_config")]
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) generation_config: Option<Value>,
    #[serde(rename = "safetySettings", alias = "safety_settings")]
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) safety_settings: Option<Value>,
    #[serde(rename = "toolConfig", alias = "tool_config")]
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) tool_config: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) provider: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) usage: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) transforms: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) models: Option<Vec<ModelName>>,
    #[serde(skip_serializing_if = "Option::is_none")]
            pub(super) route: Option<String>,
        }
    };
}
protocol!(Messages { messages: Vec<Message>, system: Content, input: Content, contents: Content, tools: Vec<Tool> });
protocol!(Responses { input: Content, tools: Vec<Tool>, max_tool_calls: u64 });
protocol!(Chat { messages: Vec<Message>, tools: Vec<Tool>, functions: Vec<Function> });
protocol!(Gemini { contents: Content, #[serde(rename = "systemInstruction", alias = "system_instruction")] system_instruction: Content, tools: Vec<Tool> });

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
        let tools = match &admitted {
            Self::Messages(r) => &r.tools,
            Self::Responses(r) => &r.tools,
            Self::Chat(r) => &r.tools,
            Self::Gemini(r) => &r.tools,
        };
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
            Self::Tagged(TaggedTool::Function { .. } | TaggedTool::Custom { .. }) => true,
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
struct Prediction {
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
        role: String,
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
struct OutputConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<Value>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Diagnostics {
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_message_id: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Safeguard {
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
