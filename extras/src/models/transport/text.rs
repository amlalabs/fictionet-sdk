//! Credential removal across the text pieces a provider's caller assembles.

use super::*;
use std::collections::BTreeMap;

use super::super::response::{Channel, content};

/// Scrub whole matches and return the first record whose suffix might still
/// become a credential. Records before it can be released without guessing.
pub(super) fn scrub(values: &mut [Value], secret: &Secret, end: bool) -> usize {
    let mut channels: BTreeMap<Channel, Vec<(usize, usize, String)>> = BTreeMap::new();
    for (index, value) in values.iter_mut().enumerate() {
        let mut field = 0;
        content(value, &mut |channel, text| {
            channels
                .entry(channel)
                .or_default()
                .push((index, field, text.clone()));
            field += 1;
        });
    }
    let mut replacements = BTreeMap::new();
    let mut ready = values.len();
    for (channel, pieces) in channels {
        if channel == Channel::Arguments {
            for (index, path, text) in pieces {
                if let Some(safe) = arguments(&text, secret) {
                    replacements.insert((index, path), safe);
                }
            }
            continue;
        }
        let joined: String = pieces.iter().map(|(_, _, text)| text.as_str()).collect();
        if matches!(channel, Channel::Tool(_, _)) {
            if !end {
                ready = ready.min(pieces[0].0);
                continue;
            }
            if let Some(safe) = arguments(&joined, secret) {
                let mut safe = Some(safe);
                for (index, path, _) in pieces {
                    replacements.insert((index, path), safe.take().unwrap_or_default());
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
            replacements.insert((index, path), safe);
        }
    }
    for (index, value) in values.iter_mut().enumerate() {
        let mut field = 0;
        content(value, &mut |_, text| {
            if let Some(safe) = replacements.remove(&(index, field)) {
                *text = safe;
            }
            field += 1;
        });
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

/// Tool arguments re-encoded without the credential, when their decoded
/// JSON holds it. Other arguments keep their exact text.
fn arguments(text: &str, secret: &Secret) -> Option<String> {
    if !holds(text, secret) {
        return None;
    }
    let mut arguments = serde_json::from_str::<Value>(text).ok()?;
    scrub_json(&mut arguments, secret);
    Some(serde_json::to_string(&arguments).expect("tool arguments"))
}
