//! The names serde gives an enum's unit variants. The worlds' enums derive
//! `Serialize` and `Deserialize` with `rename_all`, and use these names in
//! event fields and on the command line too, so each name is written once.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// The name serde writes for `value`, a unit variant.
///
/// # Panics
///
/// If `value` does not serialize as a string.
pub fn name(value: &impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        other => panic!("not a unit variant: {other:?}"),
    }
}

/// The unit variant serde reads from `text`, or `None` for any other text.
pub fn parse<T: DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_value(Value::String(text.into())).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Mode {
        StaleRevision,
        Hijack,
    }

    #[test]
    fn names_round_trip_and_reject_other_text() {
        assert_eq!(name(&Mode::StaleRevision), "stale_revision");
        assert_eq!(parse::<Mode>("hijack"), Some(Mode::Hijack));
        for text in ["", "Hijack", "StaleRevision", " hijack", "other"] {
            assert_eq!(parse::<Mode>(text), None, "{text:?}");
        }
    }
}
