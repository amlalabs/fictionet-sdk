//! Decoded provider input containers. Unknown fields and remote references fail closed.
//!
//! Inert sampling options and client function arguments are opaque. Provider content
//! is decoded recursively, including nested tool results and inline documents.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) model: Option<ModelName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    messages: Option<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contents: Option<Content>,
    #[serde(rename = "systemInstruction", alias = "system_instruction")]
    #[serde(skip_serializing_if = "Option::is_none")]
    system_instruction: Option<Content>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    functions: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instructions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_output_tokens: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_completion_tokens: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_k: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function_call: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<Diagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safeguards: Option<Vec<Safeguard>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safety_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt_cache_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt_cache_retention: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    store: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_response_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    include: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reasoning_effort: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thinking: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_config: Option<OutputConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context_management: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frequency_penalty: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presence_penalty: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logit_bias: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logprobs: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_logprobs: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modalities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audio: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prediction: Option<Prediction>,
    #[serde(rename = "generationConfig", alias = "generation_config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    generation_config: Option<Value>,
    #[serde(rename = "safetySettings", alias = "safety_settings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    safety_settings: Option<Value>,
    #[serde(rename = "toolConfig", alias = "tool_config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_config: Option<Value>,
    // OpenRouter's inert routing and accounting options.
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transforms: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    models: Option<Vec<ModelName>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prediction {
    #[serde(rename = "type")]
    kind: PredictionKind,
    content: Content,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum PredictionKind {
    Content,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Content {
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

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum Block {
    Typed(TypedBlock),
    Message(Message),
    Parts(Parts),
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Message {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<Content>,
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
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Parts {
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
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum TypedBlock {
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

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Source {
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

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum Image {
    Data(InlineData),
    Object(ImageObject),
}

struct InlineData(String);
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImageObject {
    url: InlineData,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InlineBytes {
    #[serde(rename = "mimeType", alias = "mime_type")]
    mime_type: String,
    data: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InputAudio {
    data: String,
    format: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FunctionCall {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    args: Value,
}
#[derive(Deserialize, Serialize)]
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OutputConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Diagnostics {
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_message_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
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
impl Envelope {
    pub(super) fn decode(body: &Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(body.clone())
    }
    pub(super) fn value(&self) -> Value {
        serde_json::to_value(self).expect("admitted provider request")
    }
}
