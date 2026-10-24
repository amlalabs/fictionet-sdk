//! Credential removal across the text pieces a provider's caller assembles.

use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Channel {
    Text(u64),
    Thinking(u64),
    Tool(u64, u64),
}

fn fields(value: &Value) -> Vec<(Channel, String)> {
    let mut fields = Vec::new();
    let mut add = |channel, path: String| {
        if value.pointer(&path).is_some_and(Value::is_string) {
            fields.push((channel, path));
        }
    };
    if let Some(content) = value["content"].as_array() {
        for (index, _) in content.iter().enumerate() {
            add(Channel::Text(0), format!("/content/{index}/text"));
            add(Channel::Thinking(0), format!("/content/{index}/thinking"));
        }
    }
    add(Channel::Text(0), "/content_block/text".into());
    add(Channel::Thinking(0), "/content_block/thinking".into());
    add(Channel::Text(0), "/delta/text".into());
    add(Channel::Thinking(0), "/delta/thinking".into());
    add(
        Channel::Tool(0, value["index"].as_u64().unwrap_or(0)),
        "/delta/partial_json".into(),
    );
    // Responses uses a string delta and identifies its output item explicitly.
    let output = value["output_index"].as_u64().unwrap_or(0);
    let delta_channel = if value["type"] == "response.function_call_arguments.delta" {
        Channel::Tool(0, output)
    } else {
        Channel::Text(output)
    };
    add(delta_channel, "/delta".into());
    if let Some(choices) = value["choices"].as_array() {
        for (index, choice) in choices.iter().enumerate() {
            let channel = choice["index"].as_u64().unwrap_or(index as u64);
            for container in ["message", "delta"] {
                add(
                    Channel::Text(channel),
                    format!("/choices/{index}/{container}/content"),
                );
                add(
                    Channel::Thinking(channel),
                    format!("/choices/{index}/{container}/reasoning_content"),
                );
                if let Some(tools) = choice[container]["tool_calls"].as_array() {
                    for (tool_index, tool) in tools.iter().enumerate() {
                        add(
                            Channel::Tool(
                                channel,
                                tool["index"].as_u64().unwrap_or(tool_index as u64),
                            ),
                            format!(
                                "/choices/{index}/{container}/tool_calls/{tool_index}/function/arguments"
                            ),
                        );
                    }
                }
            }
        }
    }
    if let Some(candidates) = value["candidates"].as_array() {
        for (index, candidate) in candidates.iter().enumerate() {
            if let Some(parts) = candidate["content"]["parts"].as_array() {
                for (part, _) in parts.iter().enumerate() {
                    add(
                        Channel::Text(index as u64),
                        format!("/candidates/{index}/content/parts/{part}/text"),
                    );
                }
            }
        }
    }
    // Complete Responses output is assembled in the same way as streamed text.
    if let Some(output) = value["output"].as_array() {
        for (index, item) in output.iter().enumerate() {
            add(
                Channel::Tool(0, index as u64),
                format!("/output/{index}/arguments"),
            );
            if let Some(content) = item["content"].as_array() {
                for (part, _) in content.iter().enumerate() {
                    add(
                        Channel::Text(index as u64),
                        format!("/output/{index}/content/{part}/text"),
                    );
                }
            }
        }
    }
    fields
}

/// Scrub whole matches and return the first record whose suffix might still
/// become a credential. Records before it can be released without guessing.
pub(super) fn scrub(values: &mut [Value], secret: &Secret, end: bool) -> usize {
    let mut channels: BTreeMap<Channel, Vec<(usize, String, String)>> = BTreeMap::new();
    for (index, value) in values.iter().enumerate() {
        for (channel, path) in fields(value) {
            let text = value.pointer(&path).unwrap().as_str().unwrap().to_owned();
            channels
                .entry(channel)
                .or_default()
                .push((index, path, text));
        }
    }
    let mut ready = values.len();
    for (channel, pieces) in channels {
        let joined: String = pieces.iter().map(|(_, _, text)| text.as_str()).collect();
        if matches!(channel, Channel::Tool(_, _)) {
            if !end {
                ready = ready.min(pieces[0].0);
                continue;
            }
            if let Ok(mut arguments) = serde_json::from_str::<Value>(&joined) {
                scrub(std::slice::from_mut(&mut arguments), secret, true);
                let mut encoded = Some(serde_json::to_string(&arguments).expect("tool arguments"));
                for (index, path, _) in pieces {
                    *values[index].pointer_mut(&path).unwrap() =
                        Value::String(encoded.take().unwrap_or_default());
                }
                continue;
            }
        }
        let matches: Vec<_> = joined
            .match_indices(&secret.value)
            .map(|(at, text)| at..at + text.len())
            .collect();
        let keep = if end {
            0
        } else {
            (1..secret.value.len())
                .rev()
                .find(|n| joined.as_bytes().ends_with(&secret.value.as_bytes()[..*n]))
                .unwrap_or(0)
        };
        let mut offset = 0;
        for (index, path, text) in pieces {
            let start = offset;
            let finish = start + text.len();
            offset = finish;
            if keep > 0 && finish > joined.len() - keep {
                ready = ready.min(index);
            }
            let mut safe = String::new();
            let mut cursor = start;
            for range in &matches {
                if range.end <= start || range.start >= finish {
                    continue;
                }
                if range.start >= start {
                    safe.push_str(&joined[cursor..range.start]);
                    safe.push_str(&format!("<{}>", secret.name));
                }
                cursor = range.end.min(finish);
            }
            safe.push_str(&joined[cursor..finish]);
            *values[index].pointer_mut(&path).unwrap() = Value::String(safe);
        }
    }
    for value in values {
        // Snapshots inside SSE terminal events are independent complete answers.
        for container in ["response", "message"] {
            if let Some(nested) = value.get_mut(container) {
                scrub(std::slice::from_mut(nested), secret, true);
            }
        }
        scrub_json(value, secret);
    }
    ready
}
