//! A small JSON writer: the dashboard's messages are flat enough that a
//! serializer would cost more than it saves.

use std::fmt::Write;

/// Appends `s` as a JSON string, quotes included.
pub(crate) fn string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // `<` too, so a string can never close a script element.
            c if (c as u32) < 0x20 || c == '<' || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `s` as a JSON string.
pub(crate) fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    string(&mut out, s);
    out
}

/// An object written field by field.
pub(crate) struct Object {
    out: String,
    first: bool,
}

impl Object {
    pub(crate) fn new() -> Object {
        Object { out: String::from("{"), first: true }
    }

    fn key(&mut self, k: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        string(&mut self.out, k);
        self.out.push(':');
    }

    pub(crate) fn str(mut self, k: &str, v: &str) -> Object {
        self.key(k);
        string(&mut self.out, v);
        self
    }

    pub(crate) fn opt_str(self, k: &str, v: Option<&str>) -> Object {
        match v {
            Some(v) => self.str(k, v),
            None => self.raw(k, "null"),
        }
    }

    pub(crate) fn num(mut self, k: &str, v: impl std::fmt::Display) -> Object {
        self.key(k);
        let _ = write!(self.out, "{v}");
        self
    }

    /// Seconds, to the microsecond.
    pub(crate) fn secs(self, k: &str, d: std::time::Duration) -> Object {
        self.raw(k, &format!("{:.6}", d.as_secs_f64()))
    }

    pub(crate) fn bool(self, k: &str, v: bool) -> Object {
        self.raw(k, if v { "true" } else { "false" })
    }

    /// A value that is JSON already.
    pub(crate) fn raw(mut self, k: &str, v: &str) -> Object {
        self.key(k);
        self.out.push_str(v);
        self
    }

    pub(crate) fn done(mut self) -> String {
        self.out.push('}');
        self.out
    }
}

/// An array of values that are JSON already.
pub(crate) fn array<I: IntoIterator<Item = S>, S: AsRef<str>>(items: I) -> String {
    let mut out = String::from("[");
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(item.as_ref());
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        assert_eq!(quote("a\"b\\c\n</script>\u{1}"), r#""a\"b\\c\n\u003c/script>\u0001""#);
    }

    #[test]
    fn objects_and_arrays() {
        let o = Object::new().str("id", "t1").num("line", 5).bool("ok", true).opt_str("p", None).done();
        assert_eq!(o, r#"{"id":"t1","line":5,"ok":true,"p":null}"#);
        assert_eq!(array(["1", "2"]), "[1,2]");
    }
}

/// A value of a flat JSON object: requests hold nothing deeper.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Scalar {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

impl Scalar {
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Scalar::Str(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            Scalar::Num(n) if *n >= 0.0 && n.fract() == 0.0 && *n < 9.0e15 => Some(*n as u64),
            Scalar::Str(s) => s.parse().ok(),
            _ => None,
        }
    }
}

/// Parses a JSON object whose values are strings, numbers, booleans or
/// null. `None` for anything else.
pub(crate) fn parse_flat(text: &str) -> Option<std::collections::HashMap<String, Scalar>> {
    let mut p = Parser { b: text.as_bytes(), i: 0 };
    let mut out = std::collections::HashMap::new();
    p.ws();
    p.eat(b'{')?;
    p.ws();
    if p.peek() == Some(b'}') {
        p.i += 1;
    } else {
        loop {
            p.ws();
            let k = p.string()?;
            p.ws();
            p.eat(b':')?;
            p.ws();
            let v = match p.peek()? {
                b'"' => Scalar::Str(p.string()?),
                b't' => p.word("true", Scalar::Bool(true))?,
                b'f' => p.word("false", Scalar::Bool(false))?,
                b'n' => p.word("null", Scalar::Null)?,
                _ => Scalar::Num(p.number()?),
            };
            out.insert(k, v);
            p.ws();
            match p.peek()? {
                b',' => p.i += 1,
                b'}' => {
                    p.i += 1;
                    break;
                }
                _ => return None,
            }
        }
    }
    p.ws();
    (p.i == p.b.len()).then_some(out)
}

/// Whether `text` is exactly one JSON value, with any whitespace around it.
pub(crate) fn is_value(text: &str) -> bool {
    let mut p = Parser { b: text.as_bytes(), i: 0 };
    p.ws();
    let ok = p.value(0).is_some();
    p.ws();
    ok && p.i == p.b.len()
}

/// `text`, a valid JSON value, with the whitespace between tokens taken
/// out, so it fits on one line.
pub(crate) fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in text.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !c.is_whitespace() {
            out.push(c);
        }
    }
    out
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> Option<()> {
        (self.peek()? == c).then(|| self.i += 1)
    }
    fn word(&mut self, w: &str, v: Scalar) -> Option<Scalar> {
        self.b[self.i..].starts_with(w.as_bytes()).then(|| {
            self.i += w.len();
            v
        })
    }
    /// Skips one value of any kind, nested at most 64 deep.
    fn value(&mut self, depth: usize) -> Option<()> {
        if depth > 64 {
            return None;
        }
        match self.peek()? {
            b'"' => self.string().map(drop),
            b't' => self.word("true", Scalar::Null).map(drop),
            b'f' => self.word("false", Scalar::Null).map(drop),
            b'n' => self.word("null", Scalar::Null).map(drop),
            open @ (b'{' | b'[') => {
                let close = if open == b'{' { b'}' } else { b']' };
                self.i += 1;
                self.ws();
                if self.peek()? == close {
                    self.i += 1;
                    return Some(());
                }
                loop {
                    self.ws();
                    if open == b'{' {
                        self.string()?;
                        self.ws();
                        self.eat(b':')?;
                        self.ws();
                    }
                    self.value(depth + 1)?;
                    self.ws();
                    match self.peek()? {
                        b',' => self.i += 1,
                        c if c == close => {
                            self.i += 1;
                            return Some(());
                        }
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => self.strict_number(),
            _ => None,
        }
    }

    /// Skips a number written as JSON allows: no leading zeros, digits on
    /// both sides of a point, an optional exponent.
    fn strict_number(&mut self) -> Option<()> {
        let digits = |p: &mut Self| {
            let start = p.i;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.i += 1;
            }
            p.i - start
        };
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => {
                digits(self);
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if digits(self) == 0 {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                return None;
            }
        }
        Some(())
    }

    fn number(&mut self) -> Option<f64> {
        let start = self.i;
        while matches!(self.peek(), Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')) {
            self.i += 1;
        }
        std::str::from_utf8(&self.b[start..self.i]).ok()?.parse().ok()
    }
    fn string(&mut self) -> Option<String> {
        self.eat(b'"')?;
        let mut out = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).ok(),
                // JSON strings hold no raw control characters.
                0..0x20 => return None,
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'u' => {
                            let hex = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
                            self.i += 4;
                            let ch = char::from_u32(u32::from_str_radix(hex, 16).ok()?).unwrap_or('\u{fffd}');
                            let mut buf = [0; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None,
                    }
                }
                c => out.push(c),
            }
        }
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn flat_objects_parse() {
        let o = parse_flat(r#" {"op":"packets", "link":"e5","after":12, "x":true,"y":null,"s":"a\"A"} "#).unwrap();
        assert_eq!(o["op"].as_str(), Some("packets"));
        assert_eq!(o["after"].as_u64(), Some(12));
        assert_eq!(o["x"], Scalar::Bool(true));
        assert_eq!(o["s"].as_str(), Some("a\"A"));
        assert!(parse_flat("{}").unwrap().is_empty());
        assert!(parse_flat(r#"{"a":[1]}"#).is_none());
        assert!(parse_flat(r#"{"a":1"#).is_none());
        assert!(parse_flat(r#"{"a":1} x"#).is_none());
    }

    #[test]
    fn values_are_checked() {
        for ok in [r#"{"host":"a","n":[1,2.5e3,{"x":null}],"t":true}"#, " 12 ", r#""s""#, "[]", "{}"] {
            assert!(is_value(ok), "{ok}");
        }
        for bad in ["", "{", r#"{"a":}"#, "[1,]", "1 2", "nul", r#"{"a" 1}"#, "{'a':1}", "01", "1.", ".5", "-", "1e", "\"a\nb\""] {
            assert!(!is_value(bad), "{bad}");
        }
        for ok in ["0", "-0.5", "1e10", "2.5E-3", "[-1,0.0]"] {
            assert!(is_value(ok), "{ok}");
        }
        assert_eq!(compact("{\n  \"a b\": [1, 2],\n  \"c\": \"x \\\" y\"\n}"), r#"{"a b":[1,2],"c":"x \" y"}"#);
    }
}
