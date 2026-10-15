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
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "POL-INFALLIBLE: fmt::Write for String never returns Err"
                )]
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `s` as a JSON string.
#[cfg(feature = "observe")]
pub(crate) fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    string(&mut out, s);
    out
}

/// An object written field by field.
#[cfg(feature = "observe")]
pub(crate) struct Object {
    out: String,
    first: bool,
}

#[cfg(feature = "observe")]
impl Object {
    pub(crate) fn new() -> Object {
        Object {
            out: String::from("{"),
            first: true,
        }
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
        #[expect(
            clippy::let_underscore_must_use,
            reason = "POL-INFALLIBLE: fmt::Write for String never returns Err"
        )]
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
#[cfg(feature = "observe")]
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

#[cfg(all(test, feature = "observe"))]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        assert_eq!(
            quote("a\"b\\c\n</script>\u{1}"),
            r#""a\"b\\c\n\u003c/script>\u0001""#
        );
    }

    #[test]
    fn objects_and_arrays() {
        let o = Object::new()
            .str("id", "t1")
            .num("line", 5)
            .bool("ok", true)
            .opt_str("p", None)
            .done();
        assert_eq!(o, r#"{"id":"t1","line":5,"ok":true,"p":null}"#);
        assert_eq!(array(["1", "2"]), "[1,2]");
    }
}

/// A value of a flat JSON object: requests hold nothing deeper.
#[derive(Clone, Debug, PartialEq)]
#[cfg(feature = "observe")]
pub(crate) enum Scalar {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

#[cfg(feature = "observe")]
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
#[cfg(feature = "observe")]
pub(crate) fn parse_flat(text: &str) -> Option<std::collections::HashMap<String, Scalar>> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    let mut out = std::collections::HashMap::new();
    p.ws();
    p.eat(b'{')?;
    p.ws();
    if p.peek() == Some(b'}') {
        p.i += 1;
    } else {
        loop {
            p.ws();
            let k = p.string(false)?;
            p.ws();
            p.eat(b':')?;
            p.ws();
            let v = match p.peek()? {
                b'"' => Scalar::Str(p.string(false)?),
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

#[cfg(feature = "std")]
pub(crate) struct Parser<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) i: usize,
}

#[cfg(feature = "std")]
impl Parser<'_> {
    pub(crate) fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    pub(crate) fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    pub(crate) fn eat(&mut self, c: u8) -> Option<()> {
        (self.peek()? == c).then(|| self.i += 1)
    }
    fn word<T>(&mut self, w: &str, v: T) -> Option<T> {
        self.b[self.i..].starts_with(w.as_bytes()).then(|| {
            self.i += w.len();
            v
        })
    }
    #[cfg(feature = "observe")]
    fn number(&mut self) -> Option<f64> {
        let start = self.i;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.i += 1;
        }
        std::str::from_utf8(&self.b[start..self.i])
            .ok()?
            .parse()
            .ok()
    }
    // Flat requests replace lone surrogates; envelopes reject them.
    pub(crate) fn string(&mut self, strict: bool) -> Option<String> {
        let mut out = Vec::new();
        self.scan_string(strict, |bytes| out.extend_from_slice(bytes))?;
        String::from_utf8(out).ok()
    }

    fn scan_string(&mut self, strict: bool, mut emit: impl FnMut(&[u8])) -> Option<()> {
        self.eat(b'"')?;
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Some(()),
                // JSON strings hold no raw control characters.
                0..0x20 => return None,
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => emit(&[e]),
                        b'n' => emit(b"\n"),
                        b't' => emit(b"\t"),
                        b'r' => emit(b"\r"),
                        b'b' => emit(&[8]),
                        b'f' => emit(&[12]),
                        b'u' => {
                            let hex = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
                            if strict && !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                                return None;
                            }
                            self.i += 4;
                            let mut code = u32::from_str_radix(hex, 16).ok()?;
                            if (0xd800..=0xdbff).contains(&code)
                                && self.b[self.i..].starts_with(b"\\u")
                            {
                                let low = self
                                    .b
                                    .get(self.i + 2..self.i + 6)
                                    .and_then(|hex| std::str::from_utf8(hex).ok())
                                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                                    .filter(|low| (0xdc00..=0xdfff).contains(low));
                                if let Some(low) = low {
                                    code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
                                    self.i += 6;
                                }
                            }
                            let ch = match char::from_u32(code) {
                                Some(ch) => ch,
                                None if strict => return None,
                                None => '\u{fffd}',
                            };
                            let mut buf = [0; 4];
                            emit(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None,
                    }
                }
                c => emit(&[c]),
            }
        }
    }

    fn skip_number(&mut self) -> Option<()> {
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek()? {
            b'0' => self.i += 1,
            b'1'..=b'9' => self.digits()?,
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            self.digits()?;
        }
        Some(())
    }

    fn digits(&mut self) -> Option<()> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        (self.i > start).then_some(())
    }

    fn skip_key(&mut self) -> Option<()> {
        self.scan_string(true, |_| {})?;
        self.ws();
        self.eat(b':')
    }

    /// Validates one JSON value without allocating its contents. The caller
    /// checks UTF-8. A stack of closing delimiters keeps nesting off the call stack.
    pub(crate) fn skip_value(&mut self) -> Option<()> {
        let mut stack = Vec::new();
        loop {
            self.ws();
            match self.peek()? {
                b'{' | b'[' => {
                    let end = if self.peek()? == b'{' { b'}' } else { b']' };
                    self.i += 1;
                    self.ws();
                    if self.eat(end).is_none() {
                        stack.push(end);
                        if end == b'}' {
                            self.skip_key()?;
                        }
                        continue;
                    }
                }
                b'"' => self.scan_string(true, |_| {})?,
                b't' => self.word("true", ())?,
                b'f' => self.word("false", ())?,
                b'n' => self.word("null", ())?,
                _ => self.skip_number()?,
            }
            loop {
                let Some(&end) = stack.last() else {
                    return Some(());
                };
                self.ws();
                if self.eat(end).is_some() {
                    stack.pop();
                } else {
                    self.eat(b',')?;
                    self.ws();
                    if end == b'}' {
                        self.skip_key()?;
                    }
                    break;
                }
            }
        }
    }
}

#[cfg(all(test, feature = "observe"))]
mod parse_tests {
    use super::*;

    #[test]
    fn escaped_surrogates() {
        let o = parse_flat(r#"{"pair":"\uD83D\uDE00","high":"\uD83D","low":"\uDE00","text":"\uD83Dx","bmp":"\uD83D\u0041","twice":"\uD83D\uD83D\uDE00"}"#).unwrap();
        assert_eq!(o["pair"].as_str(), Some("😀"));
        assert_eq!(o["high"].as_str(), Some("�"));
        assert_eq!(o["low"].as_str(), Some("�"));
        assert_eq!(o["text"].as_str(), Some("�x"));
        assert_eq!(o["bmp"].as_str(), Some("�A"));
        assert_eq!(o["twice"].as_str(), Some("�😀"));
        assert!(parse_flat(r#"{"s":"\uD83D\uZZZZ"}"#).is_none());
        assert!(parse_flat(r#"{"s":"\uD83D\uDE"}"#).is_none());
    }

    #[test]
    fn flat_objects_parse() {
        let o = parse_flat(
            r#" {"op":"packets", "link":"e5","after":12, "x":true,"y":null,"s":"a\"A"} "#,
        )
        .unwrap();
        assert_eq!(o["op"].as_str(), Some("packets"));
        assert_eq!(o["after"].as_u64(), Some(12));
        assert_eq!(o["x"], Scalar::Bool(true));
        assert_eq!(o["s"].as_str(), Some("a\"A"));
        assert!(parse_flat("{}").unwrap().is_empty());
        assert!(parse_flat(r#"{"a":[1]}"#).is_none());
        assert!(parse_flat(r#"{"a":1"#).is_none());
        assert!(parse_flat(r#"{"a":1} x"#).is_none());
    }
}

/// Appends `b` in lowercase hex, two digits a byte.
pub(crate) fn push_hex(out: &mut String, b: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    out.reserve(b.len() * 2);
    for &x in b {
        out.push(DIGITS[(x >> 4) as usize] as char);
        out.push(DIGITS[(x & 15) as usize] as char);
    }
}
