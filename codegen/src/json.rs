//! A bounded JSON reader. Numbers retain their decimal text.
use crate::{Error, ErrorKind, MAX_INPUT, MAX_JSON_DEPTH, MAX_JSON_ELEMENTS};
use std::collections::BTreeMap;

#[derive(Debug)]
pub(crate) enum Value {
    Null,
    Bool,
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}
pub(crate) fn parse(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > MAX_INPUT {
        return Err(Error::new(
            ErrorKind::InputLimit,
            "input",
            "MAX_INPUT exceeded",
        ));
    }
    let mut p = Parser {
        bytes,
        pos: 0,
        elements: 0,
    };
    let value = p.value(0)?;
    p.space();
    if p.pos != bytes.len() {
        return Err(p.error("trailing JSON"));
    }
    Ok(value)
}
struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    elements: usize,
}
impl Parser<'_> {
    fn error(&self, message: &str) -> Error {
        Error::new(ErrorKind::JsonSyntax, format!("byte {}", self.pos), message)
    }
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }
    fn expect(&mut self, b: u8) -> Result<(), Error> {
        if self.peek() != Some(b) {
            return Err(self.error("unexpected byte"));
        }
        self.pos += 1;
        Ok(())
    }
    fn element(&mut self) -> Result<(), Error> {
        if self.elements >= MAX_JSON_ELEMENTS {
            return Err(Error::new(
                ErrorKind::InputLimit,
                format!("byte {}", self.pos),
                "MAX_JSON_ELEMENTS exceeded",
            ));
        }
        self.elements += 1;
        Ok(())
    }
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth >= MAX_JSON_DEPTH {
            return Err(Error::new(
                ErrorKind::InputLimit,
                format!("byte {}", self.pos),
                "MAX_JSON_DEPTH exceeded",
            ));
        }
        self.element()?;
        self.space();
        match self.peek() {
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => {
                self.pos += 1;
                self.space();
                let mut values = Vec::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Value::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.space();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        break;
                    }
                    self.expect(b',')?;
                }
                Ok(Value::Array(values))
            }
            Some(b'{') => {
                self.pos += 1;
                self.space();
                let mut values = BTreeMap::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Value::Object(values));
                }
                loop {
                    self.element()?;
                    self.space();
                    let key = self.string()?;
                    self.space();
                    self.expect(b':')?;
                    let value = self.value(depth + 1)?;
                    if values.insert(key, value).is_some() {
                        return Err(self.error("duplicate object key"));
                    }
                    self.space();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        break;
                    }
                    self.expect(b',')?;
                }
                Ok(Value::Object(values))
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Value::Bool)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Value::Bool)
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Value::Null)
            }
            _ => Err(self.error("expected JSON value")),
        }
    }
    fn literal(&mut self, literal: &[u8]) -> Result<(), Error> {
        for &b in literal {
            self.expect(b)?;
        }
        Ok(())
    }
    fn digits(&mut self) -> Result<(), Error> {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(self.error("expected digit"));
        }
        Ok(())
    }
    fn number(&mut self) -> Result<Value, Error> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        if self.peek() == Some(b'0') {
            self.pos += 1;
        } else {
            self.digits()?;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.digits()?;
        }
        let bytes = self
            .bytes
            .get(start..self.pos)
            .ok_or_else(|| self.error("number range"))?;
        let text = std::str::from_utf8(bytes).map_err(|_| self.error("invalid number"))?;
        Ok(Value::Number(text.into()))
    }
    fn hex(&mut self) -> Result<u32, Error> {
        let mut n = 0;
        for _ in 0..4 {
            let b = self
                .peek()
                .ok_or_else(|| self.error("short Unicode escape"))?;
            let digit = char::from(b)
                .to_digit(16)
                .ok_or_else(|| self.error("invalid Unicode escape"))?;
            self.pos += 1;
            n = n * 16 + digit;
        }
        Ok(n)
    }
    fn string(&mut self) -> Result<String, Error> {
        self.expect(b'"')?;
        let mut result = String::new();
        let mut start = self.pos;
        loop {
            match self.peek() {
                Some(b'"' | b'\\') => {
                    let bytes = self
                        .bytes
                        .get(start..self.pos)
                        .ok_or_else(|| self.error("string range"))?;
                    result.push_str(
                        std::str::from_utf8(bytes).map_err(|_| self.error("invalid UTF-8"))?,
                    );
                    if self.peek() == Some(b'"') {
                        self.pos += 1;
                        return Ok(result);
                    }
                    self.pos += 1;
                    let escape = self.peek().ok_or_else(|| self.error("short escape"))?;
                    self.pos += 1;
                    result.push(match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut n = self.hex()?;
                            if (0xd800..=0xdbff).contains(&n) {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let low = self.hex()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err(self.error("invalid surrogate pair"));
                                }
                                n = 0x10000 + ((n - 0xd800) << 10) + low - 0xdc00;
                            }
                            char::from_u32(n).ok_or_else(|| self.error("invalid Unicode scalar"))?
                        }
                        _ => return Err(self.error("invalid escape")),
                    });
                    start = self.pos;
                }
                Some(0..=31) => return Err(self.error("control byte in string")),
                Some(_) => self.pos += 1,
                None => return Err(self.error("unterminated string")),
            }
        }
    }
}
