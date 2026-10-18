//! Header lookup for the legacy request logs.

use fictionet::events::Event as Entry;
use fictionet::stdlib::protocols::json::Value as J;

/// The first matching header's string value, or none if it is missing or malformed.
pub(super) fn header<'a>(e: &'a Entry, name: &str) -> Option<&'a str> {
    e.get("headers")
        .and_then(J::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(J::as_array)
        .find(|p| p.first().and_then(J::as_str) == Some(name))
        .and_then(|p| p.get(1).and_then(J::as_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_matching_name_controls_the_value() {
        let headers = fictionet::stdlib::protocols::json::parse_with(
            br#"[null, [], ["user-agent", null], ["user-agent", "later"],
                ["referer", "first"], ["referer", "second"], ["empty", ""]]"#,
            &Default::default(),
        )
        .unwrap();
        let e = Entry::new("http", "request").field("headers", headers);
        assert_eq!(header(&e, "user-agent"), None);
        assert_eq!(header(&e, "referer"), Some("first"));
        assert_eq!(header(&e, "empty"), Some(""));
        assert_eq!(header(&e, "Referer"), None);
        assert_eq!(header(&Entry::new("http", "request"), "user-agent"), None);
    }
}
