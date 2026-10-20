use serde_json::Value;

pub(super) fn s(v: &Value) -> &str {
    v.as_str().expect("corpus string")
}
pub(super) fn array(v: &Value) -> &[Value] {
    v.as_array().expect("corpus array")
}
pub(super) fn join(v: &Value, sep: &str) -> String {
    array(v).iter().map(s).collect::<Vec<_>>().join(sep)
}
pub(super) fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}
pub(super) fn quote(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~/".contains(&b) {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            write!(out, "%{b:02X}").unwrap();
        }
    }
    out
}
pub(super) fn unquote(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}
pub(super) fn prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}
pub(super) fn sentences(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut punctuation = false;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if punctuation && c.is_whitespace() {
            out.push(&s[start..i]);
            start = i + c.len_utf8();
            while let Some(&(j, c)) = it.peek() {
                if !c.is_whitespace() {
                    break;
                }
                start = j + c.len_utf8();
                it.next();
            }
        }
        punctuation = matches!(c, '.' | '!' | '?');
    }
    out.push(&s[start..]);
    out
}
pub(super) fn thousands(n: u64) -> String {
    let text = n.to_string();
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        if i > 0 && (text.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Reverses [`esc`], and the `&copy;` in site footers: the entities the
/// rendered pages use.
fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&copy;", "©")
        .replace("&amp;", "&")
}
pub(super) fn norm(s: &str) -> String {
    let s = unescape(&s.replace("\\\"", "\"").replace("\\n", " "));
    let mut out = String::new();
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !space {
                out.push(' ');
            }
            space = true;
        } else {
            out.push(c);
            space = false;
        }
    }
    out
}
pub(super) fn strings(v: &Value) -> Vec<&str> {
    match v {
        Value::String(s) => vec![s],
        Value::Array(a) => a.iter().flat_map(strings).collect(),
        Value::Object(o) => o.values().flat_map(strings).collect(),
        _ => Vec::new(),
    }
}

pub(super) fn json(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("a JSON value")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_text() {
        assert_eq!(quote("é /?+~_'"), "%C3%A9%20/%3F%2B~_%27");
        assert_eq!(unquote("%F0%9F%98%80%FF%C3%28%zz+é"), "😀��(%zz+é");
        assert_eq!(prefix("é😀abc", 3), "é😀a");
        assert_eq!(
            sentences("One. \tTwo!\nThree?  End."),
            ["One.", "Two!", "Three?", "End."]
        );
    }
    #[test]
    fn numbers_and_entities() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1234567890), "1,234,567,890");
        assert_eq!(norm(" &amp;&lt;&gt;&quot;&#x27;&copy;\\n\t"), " &<>\"'© ");
        assert_eq!(norm(&esc("&lt; <b>")), "&lt; <b>");
    }
}
