use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};

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
pub(super) fn digit(c: char) -> bool {
    use icu_properties::{CodePointMapData, props::NumericType};
    matches!(
        CodePointMapData::<NumericType>::new().get(c),
        NumericType::Decimal | NumericType::Digit
    )
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

fn numeric(n: u32) -> String {
    let n = match n {
        0 | 0xd800..=0xdfff | 0x110000.. => return "\u{fffd}".into(),
        0x80 => 0x20ac,
        0x82 => 0x201a,
        0x83 => 0x192,
        0x84 => 0x201e,
        0x85 => 0x2026,
        0x86 => 0x2020,
        0x87 => 0x2021,
        0x88 => 0x2c6,
        0x89 => 0x2030,
        0x8a => 0x160,
        0x8b => 0x2039,
        0x8c => 0x152,
        0x8e => 0x17d,
        0x91 => 0x2018,
        0x92 => 0x2019,
        0x93 => 0x201c,
        0x94 => 0x201d,
        0x95 => 0x2022,
        0x96 => 0x2013,
        0x97 => 0x2014,
        0x98 => 0x2dc,
        0x99 => 0x2122,
        0x9a => 0x161,
        0x9b => 0x203a,
        0x9c => 0x153,
        0x9e => 0x17e,
        0x9f => 0x178,
        1..=8 | 11 | 14..=31 | 127 | 0xfdd0..=0xfdef => return String::new(),
        n if n & 0xffff >= 0xfffe => return String::new(),
        n => n,
    };
    char::from_u32(n).unwrap().to_string()
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
                out.push_str(&numeric(
                    u32::from_str_radix(&digits[..len], radix).unwrap_or(u32::MAX),
                ));
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

struct PythonJson {
    ascii: bool,
}
impl serde_json::ser::Formatter for PythonJson {
    fn begin_array_value<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if !first {
            w.write_all(b", ")?;
        }
        Ok(())
    }
    fn begin_object_key<W: ?Sized + Write>(&mut self, w: &mut W, first: bool) -> io::Result<()> {
        if !first {
            w.write_all(b", ")?;
        }
        Ok(())
    }
    fn begin_object_value<W: ?Sized + Write>(&mut self, w: &mut W) -> io::Result<()> {
        w.write_all(b": ")
    }
    fn write_string_fragment<W: ?Sized + Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        if !self.ascii {
            return w.write_all(fragment.as_bytes());
        }
        for c in fragment.chars() {
            if c < '\u{7f}' {
                w.write_all(&[c as u8])?;
            } else {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    write!(w, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }
}
pub(super) fn json(v: &Value, ascii: bool) -> Vec<u8> {
    let mut out = Vec::new();
    v.serialize(&mut serde_json::Serializer::with_formatter(
        &mut out,
        PythonJson { ascii },
    ))
    .unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn python_json_strings_and_spacing() {
        let v = json!({"z": ["é\u{7f}😀\n\t\r\u{8}\u{c}\u{1}\\\"/", true, null], "a": 1});
        assert_eq!(
            String::from_utf8(super::json(&v, true)).unwrap(),
            r#"{"z": ["\u00e9\u007f\ud83d\ude00\n\t\r\b\f\u0001\\\"/", true, null], "a": 1}"#
        );
        assert_eq!(
            String::from_utf8(super::json(&json!(["é\u{7f}😀"]), false)).unwrap(),
            "[\"é\u{7f}😀\"]"
        );
    }
    #[test]
    fn python_url_text() {
        assert_eq!(quote("é /?+~_'"), "%C3%A9%20/%3F%2B~_%27");
        assert_eq!(unquote("%F0%9F%98%80%FF%C3%28%zz+é"), "😀��(%zz+é");
        assert_eq!(prefix("é😀abc", 3), "é😀a");
        assert_eq!(
            sentences("One. \tTwo!\nThree?\u{1c}End."),
            ["One.", "Two!", "Three?", "End."]
        );
    }
    #[test]
    fn python_numbers_and_entities() {
        assert!("123²٣𝟡".chars().all(digit));
        assert!(!digit('½'));
        assert!(!digit('Ⅳ'));
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1234567890), "1,234,567,890");
        assert_eq!(
            norm(" &amp;&lt;&gt;&quot;&apos;&copy;&#39;&#x1f600;\\n\t"),
            " &<>\"'©'😀 "
        );
        assert_eq!(norm("&#0;&#x80;&#xD800;&#x110000;&#x7f;"), "�€��");
    }
}
