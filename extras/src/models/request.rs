//! Decoded provider input containers. Unknown fields and remote references fail closed.
//!
//! Inert sampling options and client function arguments are opaque. Provider content
//! is decoded recursively, including nested tool results and inline documents.
#![allow(dead_code)]

use serde::{Deserialize, Deserializer, de::IgnoredAny};
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    model: Option<ModelName>,
    messages: Option<Content>,
    input: Option<Content>,
    system: Option<Content>,
    contents: Option<Content>,
    #[serde(alias = "systemInstruction")]
    system_instruction: Option<Content>,
    tools: Option<Vec<Value>>,
    functions: Option<Vec<Value>>,
    instructions: Option<String>,
    max_tokens: Option<IgnoredAny>,
    max_output_tokens: Option<IgnoredAny>,
    max_completion_tokens: Option<IgnoredAny>,
    temperature: Option<IgnoredAny>,
    top_p: Option<IgnoredAny>,
    top_k: Option<IgnoredAny>,
    stream: Option<bool>,
    stream_options: Option<IgnoredAny>,
    stop: Option<IgnoredAny>,
    stop_sequences: Option<IgnoredAny>,
    tool_choice: Option<IgnoredAny>,
    function_call: Option<IgnoredAny>,
    parallel_tool_calls: Option<bool>,
    metadata: Option<IgnoredAny>,
    client_metadata: Option<IgnoredAny>,
    user: Option<String>,
    safety_identifier: Option<String>,
    prompt_cache_key: Option<String>,
    prompt_cache_retention: Option<String>,
    cache_control: Option<IgnoredAny>,
    store: Option<bool>,
    previous_response_id: Option<String>,
    conversation: Option<String>,
    include: Option<Vec<String>>,
    reasoning: Option<IgnoredAny>,
    reasoning_effort: Option<IgnoredAny>,
    thinking: Option<IgnoredAny>,
    output_config: Option<IgnoredAny>,
    text: Option<IgnoredAny>,
    response_format: Option<IgnoredAny>,
    service_tier: Option<String>,
    truncation: Option<String>,
    context_management: Option<IgnoredAny>,
    frequency_penalty: Option<IgnoredAny>,
    presence_penalty: Option<IgnoredAny>,
    logit_bias: Option<IgnoredAny>,
    logprobs: Option<IgnoredAny>,
    top_logprobs: Option<IgnoredAny>,
    seed: Option<IgnoredAny>,
    n: Option<IgnoredAny>,
    modalities: Option<Vec<String>>,
    audio: Option<IgnoredAny>,
    prediction: Option<Prediction>,
    #[serde(rename = "generationConfig", alias = "generation_config")]
    generation_config: Option<IgnoredAny>,
    #[serde(rename = "safetySettings", alias = "safety_settings")]
    safety_settings: Option<IgnoredAny>,
    #[serde(rename = "toolConfig", alias = "tool_config")]
    tool_config: Option<IgnoredAny>,
    // OpenRouter's inert routing and accounting options.
    provider: Option<IgnoredAny>,
    usage: Option<IgnoredAny>,
    transforms: Option<Vec<String>>,
    models: Option<Vec<ModelName>>,
    route: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prediction {
    #[serde(rename = "type")]
    kind: PredictionKind,
    content: Content,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PredictionKind {
    Content,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Content {
    Text(String),
    Blocks(Vec<Content>),
    Block(Box<Block>),
    Empty(()),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Block {
    #[serde(rename = "type")]
    kind: Option<Kind>,
    role: Option<String>,
    content: Option<Content>,
    parts: Option<Content>,
    output: Option<Content>,
    source: Option<Source>,
    image_url: Option<Image>,
    file_data: Option<InlineData>,
    filename: Option<String>,
    detail: Option<String>,
    text: Option<String>,
    refusal: Option<String>,
    thinking: Option<String>,
    signature: Option<String>,
    data: Option<String>,
    id: Option<String>,
    name: Option<String>,
    tool_name: Option<String>,
    tool_use_id: Option<String>,
    call_id: Option<String>,
    input: Option<Value>,
    arguments: Option<Value>,
    is_error: Option<bool>,
    caller: Option<Value>,
    cache_control: Option<Value>,
    citations: Option<Value>,
    title: Option<String>,
    context: Option<String>,
    encrypted_content: Option<String>,
    summary: Option<Content>,
    status: Option<String>,
    phase: Option<String>,
    action: Option<Value>,
    url: Option<String>,
    encrypted_index: Option<String>,
    page_age: Option<String>,
    retrieved_at: Option<String>,
    error_code: Option<String>,
    input_audio: Option<InputAudio>,
    audio: Option<Value>,
    tool_calls: Option<Value>,
    tool_call_id: Option<String>,
    function_call: Option<Value>,
    annotations: Option<Value>,
    #[serde(rename = "inlineData", alias = "inline_data")]
    inline_data: Option<InlineBytes>,
    #[serde(rename = "functionCall")]
    gemini_call: Option<FunctionCall>,
    #[serde(rename = "functionResponse")]
    gemini_response: Option<FunctionResponse>,
    thought: Option<bool>,
    #[serde(rename = "thoughtSignature")]
    thought_signature: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Text,
    InputText,
    OutputText,
    Refusal,
    Image,
    ImageUrl,
    InputImage,
    InputFile,
    Document,
    ToolUse,
    ToolResult,
    ToolReference,
    ServerToolUse,
    WebSearchResult,
    WebSearchToolResultError,
    WebFetchResult,
    WebFetchToolResultError,
    WebSearchToolResult,
    WebFetchToolResult,
    Thinking,
    RedactedThinking,
    Message,
    FunctionCall,
    FunctionCallOutput,
    CustomToolCall,
    CustomToolCallOutput,
    Reasoning,
    SummaryText,
    WebSearchCall,
    InputAudio,
    Audio,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
#[serde(untagged)]
enum Image {
    Data(InlineData),
    Object(ImageObject),
}

struct InlineData;
impl<'de> Deserialize<'de> for InlineData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = String::deserialize(deserializer)?;
        if data.starts_with("data:")
            && data
                .split_once(',')
                .is_some_and(|(head, _)| head.ends_with(";base64"))
        {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "content must be inline base64 data",
            ))
        }
    }
}

struct ModelName;
impl<'de> Deserialize<'de> for ModelName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        if name.split(':').skip(1).any(|variant| variant == "online") || name.contains("-search-") {
            Err(serde::de::Error::custom(
                "model requires external retrieval",
            ))
        } else {
            Ok(Self)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageObject {
    url: InlineData,
    detail: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineBytes {
    #[serde(rename = "mimeType", alias = "mime_type")]
    mime_type: String,
    data: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputAudio {
    data: String,
    format: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionCall {
    id: Option<String>,
    name: String,
    args: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionResponse {
    id: Option<String>,
    name: String,
    response: Value,
    parts: Option<Content>,
    #[serde(rename = "willContinue", alias = "will_continue")]
    will_continue: Option<bool>,
    scheduling: Option<String>,
}
