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
pub(super) fn whitespace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
pub(super) fn sentences(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut punctuation = false;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if punctuation && whitespace(c) {
            out.push(&s[start..i]);
            start = i + c.len_utf8();
            while let Some(&(j, c)) = it.peek() {
                if !whitespace(c) {
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

// This is the entity subset the rendered pages and the corpus use.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        if let Some(number) = rest.strip_prefix('#') {
            let (digits, radix, offset) = if number.starts_with(['x', 'X']) {
                (&number[1..], 16, 2)
            } else {
                (number, 10, 1)
            };
            let len = digits
                .bytes()
                .take_while(|c| {
                    if radix == 16 {
                        c.is_ascii_hexdigit()
                    } else {
                        c.is_ascii_digit()
                    }
                })
                .count();
            if len > 0 {
                let code = u32::from_str_radix(&digits[..len], radix).ok();
                out.push(
                    code.and_then(char::from_u32)
                        .filter(|c| *c != '\0')
                        .unwrap_or('\u{fffd}'),
                );
                rest = &rest[offset + len..];
                rest = rest.strip_prefix(';').unwrap_or(rest);
                continue;
            }
        }
        let mut found = false;
        for (name, value) in [
            ("amp", "&"),
            ("lt", "<"),
            ("gt", ">"),
            ("quot", "\""),
            ("apos", "'"),
            ("copy", "©"),
        ] {
            if let Some(tail) = rest.strip_prefix(name)
                && (name != "apos" || tail.starts_with(';'))
            {
                out.push_str(value);
                rest = tail.strip_prefix(';').unwrap_or(tail);
                found = true;
                break;
            }
        }
        if !found {
            out.push('&');
        }
    }
    out.push_str(rest);
    out
}
pub(super) fn norm(s: &str) -> String {
    let s = unescape(&s.replace("\\\"", "\"").replace("\\n", " "));
    let mut out = String::new();
    let mut space = false;
    for c in s.chars() {
        if whitespace(c) {
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
            sentences("One. \tTwo!\nThree?\u{1c}End."),
            ["One.", "Two!", "Three?", "End."]
        );
    }
    #[test]
    fn numbers_and_entities() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1234567890), "1,234,567,890");
        assert_eq!(
            norm(" &amp;&lt;&gt;&quot;&apos;&copy;&#39;&#x1f600;\\n\t"),
            " &<>\"'©'😀 "
        );
        assert_eq!(
            norm("&#0;&#xD800;&#x110000;&#xe9;"),
            "\u{fffd}\u{fffd}\u{fffd}é"
        );
    }
}
