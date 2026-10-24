//! Provider events shared by stream assembly and credential interpretation.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub(crate) enum EventKind {
    #[serde(rename = "message_start")]
    MessageStart,
    #[serde(rename = "message_delta")]
    MessageDelta,
    #[serde(rename = "message_stop")]
    MessageStop,
    #[serde(rename = "content_block_start")]
    BlockStart,
    #[serde(rename = "content_block_delta")]
    BlockDelta,
    #[serde(rename = "content_block_stop")]
    BlockStop,
    #[serde(rename = "response.created")]
    ResponseCreated,
    #[serde(rename = "response.in_progress")]
    ResponseInProgress,
    #[serde(rename = "response.completed")]
    ResponseCompleted,
    #[serde(rename = "response.incomplete")]
    ResponseIncomplete,
    #[serde(rename = "response.failed")]
    ResponseFailed,
    #[serde(rename = "response.output_item.added")]
    ItemAdded,
    #[serde(rename = "response.output_item.done")]
    ItemDone,
    #[serde(rename = "response.function_call_arguments.delta")]
    ArgumentsDelta,
    #[serde(rename = "response.function_call_arguments.done")]
    ArgumentsDone,
    #[serde(rename = "response.refusal.delta")]
    RefusalDelta,
    #[serde(rename = "error")]
    Error,
    #[serde(other)]
    Other,
}

impl EventKind {
    pub(crate) fn read(value: &Value) -> Self {
        serde_json::from_value(value.get("type").cloned().unwrap_or(Value::Null))
            .unwrap_or(Self::Other)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Delta {
    #[serde(rename = "text_delta")]
    Text { text: String },
    #[serde(rename = "thinking_delta")]
    Thinking { thinking: String },
    #[serde(rename = "signature_delta")]
    Signature { signature: String },
    #[serde(rename = "input_json_delta")]
    InputJson { partial_json: String },
    #[serde(rename = "citations_delta")]
    Citations { citation: Value },
}

impl Delta {
    pub(crate) fn content(&mut self, index: u64, visit: &mut impl FnMut(Channel, &mut String)) {
        match self {
            Self::Text { text } => visit(Channel::Text(0), text),
            Self::Thinking { thinking } => visit(Channel::Thinking(0), thinking),
            Self::InputJson { partial_json } => visit(Channel::Tool(0, index), partial_json),
            Self::Signature { .. } | Self::Citations { .. } => {}
        }
    }
}

/// Native content uses the same block variants as provider history.
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Block {
    Native(request::TypedBlock),
    Extension(Value),
}

impl Block {
    pub(crate) fn into_content(self) -> fictionet::Result<request::Content> {
        match self {
            Self::Native(block) => Ok(request::Content::typed(block)),
            Self::Extension(value) => Ok(serde_json::from_value(value)?),
        }
    }

    pub(crate) fn tool(&self) -> Option<(&str, &str, &Value)> {
        match self {
            Self::Native(request::TypedBlock::ToolUse {
                id: Some(id),
                name,
                input,
                ..
            }) => Some((id, name, input)),
            _ => None,
        }
    }
    pub(crate) fn function(&self) -> Option<(&str, &Value, Option<&str>)> {
        match self {
            Self::Native(request::TypedBlock::FunctionCall {
                name,
                arguments,
                call_id,
                ..
            }) => Some((name, arguments, call_id.as_deref())),
            _ => None,
        }
    }
    pub(crate) fn external_function(&self) -> bool {
        matches!(
            self,
            Self::Native(
                request::TypedBlock::FunctionCall { .. }
                    | request::TypedBlock::CustomToolCall { .. }
            )
        )
    }
    pub(crate) fn show_tool(&self, id: String) -> Self {
        match self {
            Self::Native(request::TypedBlock::ToolUse { name, input, .. }) => {
                Self::Native(request::TypedBlock::ServerToolUse {
                    id,
                    name: name.clone(),
                    input: input.clone(),
                })
            }
            _ => self.clone(),
        }
    }
    pub(crate) fn set_input(&mut self, value: Value) -> fictionet::Result<()> {
        match self {
            Self::Native(request::TypedBlock::ToolUse { input, .. }) => {
                *input = value;
                Ok(())
            }
            _ => Err(Error::msg("Input delta for a non-tool block")),
        }
    }
    pub(crate) fn apply(&mut self, delta: Delta) -> fictionet::Result<()> {
        use request::TypedBlock;
        match (self, delta) {
            (Self::Native(TypedBlock::Text { text, .. }), Delta::Text { text: part }) => {
                text.push_str(&part)
            }
            (
                Self::Native(TypedBlock::Thinking { thinking, .. }),
                Delta::Thinking { thinking: part },
            ) => thinking.push_str(&part),
            (
                Self::Native(TypedBlock::Thinking { signature, .. }),
                Delta::Signature { signature: part },
            ) => signature.get_or_insert_default().push_str(&part),
            (Self::Native(TypedBlock::Text { citations, .. }), Delta::Citations { citation }) => {
                citations
                    .get_or_insert_with(|| json!([]))
                    .as_array_mut()
                    .ok_or_else(|| Error::msg("Invalid model citations"))?
                    .push(citation);
            }
            _ => return Err(Error::msg("Model delta does not match its content block")),
        }
        Ok(())
    }
    pub(crate) fn content(&mut self, channel: u64, visit: &mut impl FnMut(Channel, &mut String)) {
        use request::TypedBlock;
        match self {
            Self::Native(
                TypedBlock::Text { text, .. }
                | TypedBlock::InputText { text }
                | TypedBlock::OutputText { text, .. }
                | TypedBlock::SummaryText { text },
            ) => visit(Channel::Text(channel), text),
            Self::Native(TypedBlock::Thinking { thinking, .. }) => {
                visit(Channel::Thinking(channel), thinking)
            }
            Self::Native(TypedBlock::Refusal { refusal }) => {
                visit(Channel::Refusal(channel), refusal)
            }
            Self::Extension(value) => {
                if let Ok(mut extension) = serde_json::from_value::<TextFields>(value.clone()) {
                    if let Some(text) = &mut extension.text {
                        visit(Channel::Text(channel), text);
                    }
                    if let Some(text) = &mut extension.thinking {
                        visit(Channel::Thinking(channel), text);
                    }
                    if let Some(text) = &mut extension.refusal {
                        visit(Channel::Refusal(channel), text);
                    }
                    *value = serde_json::to_value(extension).expect("extension content");
                }
            }
            _ => {}
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TextFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    thinking: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refusal: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

pub(crate) fn blocks(
    value: &mut Value,
    channel: u64,
    visit: &mut impl FnMut(Channel, &mut String),
) {
    let Some(values) = value.as_array_mut() else {
        return;
    };
    for value in values {
        let Ok(mut block) = serde_json::from_value::<Block>(value.clone()) else {
            continue;
        };
        block.content(channel, visit);
        *value = serde_json::to_value(block).expect("native content block");
    }
}
