//! JSON: parsing text into a tree of values and writing values back as
//! text, with no I/O.
//!
//! JSON is the body format of most web APIs, and it turns up inside many
//! other protocols too: JSON-RPC, webhooks, log lines, configuration
//! files. This module follows RFC 8259 strictly. It reads one JSON text
//! into a [`Value`], and writes a [`Value`] as compact JSON text.
//!
//! Nothing here reads a socket. A world that plays a web API takes the
//! body of a request, calls [`parse`], looks at the [`Value`] it gets,
//! and writes its answer with [`Value::write`]. For a stream that carries
//! one JSON text after another, such as JSON-RPC over a TCP connection,
//! [`Values`] with [`super::codec::Stream`] takes the bytes as they come
//! and hands back each value once it is whole.
//!
//! The agent can send any bytes it likes, so the parser checks
//! everything RFC 8259 asks and nothing more. It refuses what the RFC
//! does not allow (comments, trailing commas, single quotes, leading
//! zeros, lone surrogates), and it caps the input's size, its nesting
//! depth and its number of values with [`Limits`]. A number keeps its
//! exact text next to the `f64` it reads as, so `12.50` stays `12.50`
//! and a 30-digit integer is not rounded on the way back out. An object
//! keeps its members in order, duplicate keys included, since RFC 8259
//! leaves their meaning to the reader.
//!
//! Use [`Values`] with [`super::codec::Stream`] for bounded input and EOF
//! handling. [`Value`] implements [`Wire`] for exact parsing and appending.
//! The deprecated [`Decoder`] keeps its original buffering and errors.
//!
//! ```
//! use fictionet::stdlib::json::{self, Number, Value};
//!
//! let body = br#"{"method": "transfer", "amount": 12.50, "to": "Caf\u00e9 \ud83d\ude00"}"#;
//! let request = json::parse(body).unwrap();
//! assert_eq!(request.get("method").and_then(Value::as_str), Some("transfer"));
//! let amount = request.get("amount").and_then(Value::as_number).unwrap();
//! assert_eq!(amount.text(), "12.50");
//! assert_eq!(amount.as_f64(), 12.5);
//! assert_eq!(request.get("to").and_then(Value::as_str), Some("Café 😀"));
//!
//! let reply = Value::Object(vec![
//!     ("ok".to_string(), Value::Bool(true)),
//!     ("balance".to_string(), Value::Number(Number::from_i64(-3))),
//!     ("note".to_string(), Value::from("line 1\nline 2")),
//! ]);
//! assert_eq!(reply.write().unwrap(), r#"{"ok":true,"balance":-3,"note":"line 1\nline 2"}"#);
//! ```

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use super::codec::{Decode, Step, Wire};

/// The deepest nesting of arrays and objects the parser and writer
/// accept. `[[1]]` has depth 2. [`Limits`] can lower it but not raise it.
pub const MAX_DEPTH: usize = 128;
/// The longest JSON text, in bytes, the parser reads and the writer
/// writes. [`Limits`] can lower it but not raise it.
pub const MAX_SIZE: usize = 1 << 20;
/// The most values one JSON text may hold, counting every array element,
/// every object member's value and the top-level value itself. Keys are
/// not counted. [`Limits`] can lower it but not raise it.
pub const MAX_ELEMENTS: usize = 100_000;
/// The longest number text, in bytes. RFC 8259 lets a parser limit the
/// range and precision of numbers. This keeps one number from costing
/// more to read than it could be worth.
pub const MAX_NUMBER_LEN: usize = 512;

/// The caps on one JSON text. Each field is cut to the matching constant
/// ([`MAX_DEPTH`], [`MAX_SIZE`], [`MAX_ELEMENTS`]), so a world can make
/// them tighter but never looser. The default is the constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The deepest nesting of arrays and objects. 0 allows only scalars.
    pub depth: usize,
    /// The most bytes of JSON text.
    pub size: usize,
    /// The most values, counted as for [`MAX_ELEMENTS`].
    pub elements: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { depth: MAX_DEPTH, size: MAX_SIZE, elements: MAX_ELEMENTS }
    }
}

impl Limits {
    fn depth(&self) -> usize {
        self.depth.min(MAX_DEPTH)
    }
    fn size(&self) -> usize {
        self.size.min(MAX_SIZE)
    }
    fn elements(&self) -> usize {
        self.elements.min(MAX_ELEMENTS)
    }
}

/// A JSON number: its exact text, and the `f64` that text reads as.
///
/// The text always follows the RFC 8259 number grammar and is at most
/// [`MAX_NUMBER_LEN`] bytes, so a number can be written as it was read.
/// Two numbers are equal when their texts are, so `1.0` and `1` differ.
#[derive(Clone, Debug)]
pub struct Number {
    text: String,
    value: f64,
}

impl PartialEq for Number {
    fn eq(&self, other: &Number) -> bool {
        self.text == other.text
    }
}

impl Eq for Number {}

impl core::hash::Hash for Number {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

impl Number {
    /// The number `text` spells, if it follows the RFC 8259 grammar and is
    /// no longer than [`MAX_NUMBER_LEN`]. There is no surrounding
    /// whitespace, no `+` sign, and no `NaN` or `Infinity`.
    pub fn from_text(text: &str) -> Option<Number> {
        let b = text.as_bytes();
        if b.len() > MAX_NUMBER_LEN {
            return None;
        }
        match scan_number(b, 0) {
            Ok(end) if end == b.len() => Some(Number::known(text.to_string())),
            _ => None,
        }
    }

    /// An integer, written in decimal.
    pub fn from_i64(n: i64) -> Number {
        Number::known(n.to_string())
    }

    /// An unsigned integer, written in decimal.
    pub fn from_u64(n: u64) -> Number {
        Number::known(n.to_string())
    }

    /// A float, written in the shortest text that reads back as the same
    /// `f64`. Very large and very small values use an exponent. It returns
    /// `None` for NaN and the infinities, which JSON cannot spell.
    pub fn from_f64(f: f64) -> Option<Number> {
        if !f.is_finite() {
            return None;
        }
        let mut text = format!("{f}");
        if text.len() > 24 {
            text = format!("{f:e}");
        }
        Number::from_text(&text)
    }

    /// Text already checked against the grammar.
    fn known(text: String) -> Number {
        // A text that passed the grammar always reads as an f64. A number
        // too large for one reads as an infinity.
        let value = text.parse::<f64>().unwrap_or(0.0);
        Number { text, value }
    }

    /// The number's text, exactly as it was read or made.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The nearest `f64`. A number beyond the `f64` range gives an
    /// infinity, and digits past its precision are rounded.
    pub fn as_f64(&self) -> f64 {
        self.value
    }

    /// The number as an `i64`, if its text is an integer (no fraction and
    /// no exponent) that fits.
    pub fn as_i64(&self) -> Option<i64> {
        if self.is_integer_text() { self.text.parse().ok() } else { None }
    }

    /// The number as a `u64`, if its text is a non-negative integer (no
    /// fraction and no exponent) that fits.
    pub fn as_u64(&self) -> Option<u64> {
        if !self.is_integer_text() {
            return None;
        }
        // `-0` is zero. Only the sign keeps `u64` parsing from reading it.
        if self.text == "-0" { Some(0) } else { self.text.parse().ok() }
    }

    fn is_integer_text(&self) -> bool {
        !self.text.bytes().any(|c| matches!(c, b'.' | b'e' | b'E'))
    }
}

/// One JSON value. An object is a list of members in the order they were
/// read, and may hold the same key more than once.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Value {
    /// `null`, the default.
    #[default]
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, with its exact text.
    Number(Number),
    /// A string, with its escapes decoded.
    String(String),
    /// An array of values.
    Array(Vec<Value>),
    /// An object's members, in order, duplicates kept.
    Object(Vec<(String, Value)>),
}

impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::String(s)
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Value {
        Value::Number(Number::from_i64(n))
    }
}

impl From<u64> for Value {
    fn from(n: u64) -> Value {
        Value::Number(Number::from_u64(n))
    }
}

impl From<i32> for Value {
    fn from(n: i32) -> Value {
        Value::Number(Number::from_i64(n.into()))
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Value {
        Value::Number(Number::from_u64(n.into()))
    }
}

impl From<Vec<Value>> for Value {
    fn from(items: Vec<Value>) -> Value {
        Value::Array(items)
    }
}

impl From<Number> for Value {
    fn from(n: Number) -> Value {
        Value::Number(n)
    }
}

impl Value {
    /// Whether this is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The number, if this is one.
    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }

    /// The number as an `i64`, if this is a number that
    /// [`Number::as_i64`] reads as one.
    pub fn as_i64(&self) -> Option<i64> {
        self.as_number()?.as_i64()
    }

    /// The number as a `u64`, if this is a number that
    /// [`Number::as_u64`] reads as one.
    pub fn as_u64(&self) -> Option<u64> {
        self.as_number()?.as_u64()
    }

    /// The nearest `f64`, if this is a number. See [`Number::as_f64`].
    pub fn as_f64(&self) -> Option<f64> {
        Some(self.as_number()?.as_f64())
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The members, in order, if this is an object.
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The value of the first member named `key`, if this is an object
    /// that has one. Use [`Value::as_object`] to see every duplicate.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The value as compact JSON text, within the default [`Limits`].
    pub fn write(&self) -> Result<String, Error> {
        self.write_with(&Limits::default())
    }

    /// The value as compact JSON text: no whitespace, members in order,
    /// and only the escapes a string needs. It fails, rather than write
    /// text [`parse_with`] would refuse, when the value is deeper, larger
    /// or holds more values than `limits` allow. The error's offset is how
    /// many bytes had been written, or the size limit for
    /// [`ErrorKind::TooLarge`].
    pub fn write_with(&self, limits: &Limits) -> Result<String, Error> {
        let mut w = Writer {
            out: String::new(),
            size: limits.size(),
            depth: limits.depth(),
            elements: limits.elements(),
            count: 0,
        };
        w.value(self, 0)?;
        Ok(w.out)
    }
}

/// What was wrong with a JSON text, or with a value the writer was asked
/// to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The text ended in the middle of a value, or held no value at all.
    UnexpectedEnd,
    /// A byte that cannot come where it did.
    UnexpectedByte(u8),
    /// More than whitespace after the one value a JSON text holds.
    TrailingBytes,
    /// Bytes in a string that are not UTF-8.
    InvalidUtf8,
    /// A number that breaks the grammar, such as `01`, `1.` or `-`.
    BadNumber,
    /// A number text longer than [`MAX_NUMBER_LEN`].
    NumberTooLong,
    /// A backslash followed by something other than a known escape, or a
    /// `\u` not followed by four hex digits.
    BadEscape,
    /// A `\u` escape for half of a surrogate pair without the other half.
    LoneSurrogate,
    /// A control character (below U+0020) in a string, unescaped.
    ControlCharacter,
    /// Arrays and objects nested deeper than the limit.
    TooDeep,
    /// More bytes than the size limit.
    TooLarge,
    /// More values than the element limit.
    TooManyElements,
}

/// A JSON error and the byte offset where it was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Error {
    /// What went wrong.
    pub kind: ErrorKind,
    /// The offset into the input (or, for a [`Decoder`], into the whole
    /// stream) of the byte that was wrong.
    pub offset: usize,
}

impl Error {
    fn at(kind: ErrorKind, offset: usize) -> Error {
        Error { kind, offset }
    }
}

impl core::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorKind::UnexpectedEnd => write!(f, "the text ended in the middle of a value"),
            ErrorKind::UnexpectedByte(b) => write!(f, "unexpected byte 0x{b:02x}"),
            ErrorKind::TrailingBytes => write!(f, "bytes after the value"),
            ErrorKind::InvalidUtf8 => write!(f, "a string that is not UTF-8"),
            ErrorKind::BadNumber => write!(f, "a number that breaks the grammar"),
            ErrorKind::NumberTooLong => write!(f, "a number longer than {MAX_NUMBER_LEN} bytes"),
            ErrorKind::BadEscape => write!(f, "an unknown escape"),
            ErrorKind::LoneSurrogate => write!(f, "half of a surrogate pair"),
            ErrorKind::ControlCharacter => write!(f, "an unescaped control character in a string"),
            ErrorKind::TooDeep => write!(f, "nested deeper than the limit"),
            ErrorKind::TooLarge => write!(f, "larger than the size limit"),
            ErrorKind::TooManyElements => write!(f, "more values than the limit"),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.offset)
    }
}

impl core::error::Error for Error {}

/// Reads one JSON text, within the default [`Limits`].
pub fn parse(input: &[u8]) -> Result<Value, Error> {
    parse_with(input, &Limits::default())
}

/// Reads one JSON text: optional whitespace, one value, optional
/// whitespace, and nothing else. A byte order mark is refused, as RFC
/// 8259 lets a parser do. Any value may be the top-level one.
pub fn parse_with(input: &[u8], limits: &Limits) -> Result<Value, Error> {
    let size = limits.size();
    if input.len() > size {
        return Err(Error::at(ErrorKind::TooLarge, size));
    }
    let mut p = Parser { b: input, i: 0, depth: limits.depth(), elements: limits.elements(), count: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i < input.len() {
        return Err(Error::at(ErrorKind::TrailingBytes, p.i));
    }
    Ok(v)
}

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

/// Where the number starting at `b[start]` ends, by the RFC 8259 grammar:
/// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
fn scan_number(b: &[u8], start: usize) -> Result<usize, Error> {
    let mut i = start;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        None => return Err(Error::at(ErrorKind::UnexpectedEnd, i)),
        Some(b'0') => {
            i += 1;
            if b.get(i).is_some_and(u8::is_ascii_digit) {
                return Err(Error::at(ErrorKind::BadNumber, i));
            }
        }
        Some(b'1'..=b'9') => i = digits(b, i + 1),
        Some(_) => return Err(Error::at(ErrorKind::BadNumber, i)),
    }
    if b.get(i) == Some(&b'.') {
        i = need_digits(b, i + 1)?;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        i = need_digits(b, i)?;
    }
    Ok(i)
}

fn digits(b: &[u8], mut i: usize) -> usize {
    while b.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    i
}

fn need_digits(b: &[u8], i: usize) -> Result<usize, Error> {
    match b.get(i) {
        None => Err(Error::at(ErrorKind::UnexpectedEnd, i)),
        Some(c) if c.is_ascii_digit() => Ok(digits(b, i + 1)),
        Some(_) => Err(Error::at(ErrorKind::BadNumber, i)),
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
    elements: usize,
    count: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.b.get(self.i).is_some_and(|&c| is_ws(c)) {
            self.i += 1;
        }
    }

    fn err<T>(&self, kind: ErrorKind) -> Result<T, Error> {
        Err(Error::at(kind, self.i))
    }

    /// An error for the byte at `i`: the end, or an unexpected byte.
    fn unexpected<T>(&self) -> Result<T, Error> {
        match self.b.get(self.i) {
            None => self.err(ErrorKind::UnexpectedEnd),
            Some(&c) => self.err(ErrorKind::UnexpectedByte(c)),
        }
    }

    /// One value, at nesting `depth` (the number of arrays and objects
    /// around it). Recursion stops at the depth limit, at most
    /// [`MAX_DEPTH`] levels.
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        self.count += 1;
        if self.count > self.elements {
            return self.err(ErrorKind::TooManyElements);
        }
        match self.b.get(self.i) {
            Some(b'{') | Some(b'[') if depth >= self.depth => self.err(ErrorKind::TooDeep),
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => self.unexpected(),
        }
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Result<Value, Error> {
        for &want in word {
            match self.b.get(self.i) {
                Some(&c) if c == want => self.i += 1,
                _ => return self.unexpected(),
            }
        }
        Ok(v)
    }

    fn number(&mut self) -> Result<Value, Error> {
        let start = self.i;
        let end = scan_number(self.b, start)?;
        if end - start > MAX_NUMBER_LEN {
            return Err(Error::at(ErrorKind::NumberTooLong, start));
        }
        let Ok(text) = core::str::from_utf8(&self.b[start..end]) else {
            return Err(Error::at(ErrorKind::BadNumber, start));
        };
        self.i = end;
        Ok(Value::Number(Number::known(text.to_string())))
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        self.i += 1;
        self.ws();
        let mut items = Vec::new();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return self.unexpected(),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        self.i += 1;
        self.ws();
        let mut members = Vec::new();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Value::Object(members));
        }
        loop {
            if self.b.get(self.i) != Some(&b'"') {
                return self.unexpected();
            }
            let key = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return self.unexpected();
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth)?;
            members.push((key, v));
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(members));
                }
                _ => return self.unexpected(),
            }
        }
    }

    /// A string, starting at its opening quote.
    fn string(&mut self) -> Result<String, Error> {
        self.i += 1;
        let mut out = String::new();
        let mut run = self.i;
        loop {
            match self.b.get(self.i) {
                None => return self.err(ErrorKind::UnexpectedEnd),
                Some(b'"') => {
                    self.flush(&mut out, run)?;
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.flush(&mut out, run)?;
                    out.push(self.escape()?);
                    run = self.i;
                }
                Some(&c) if c < 0x20 => return self.err(ErrorKind::ControlCharacter),
                Some(_) => self.i += 1,
            }
        }
    }

    /// Adds the raw bytes from `run` to the current byte, which is ASCII,
    /// so a whole character never spans the cut.
    fn flush(&self, out: &mut String, run: usize) -> Result<(), Error> {
        match core::str::from_utf8(&self.b[run..self.i]) {
            Ok(s) => {
                out.push_str(s);
                Ok(())
            }
            Err(e) => Err(Error::at(ErrorKind::InvalidUtf8, run + e.valid_up_to())),
        }
    }

    /// One escape, starting at its backslash. It leaves `i` after it.
    fn escape(&mut self) -> Result<char, Error> {
        let start = self.i;
        self.i += 1;
        let c = match self.b.get(self.i) {
            None => return self.err(ErrorKind::UnexpectedEnd),
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.i += 1;
                let high = self.hex4()?;
                return match high {
                    0xd800..=0xdbff => self.low_surrogate(high, start),
                    0xdc00..=0xdfff => Err(Error::at(ErrorKind::LoneSurrogate, start)),
                    _ => char::from_u32(high).ok_or(Error::at(ErrorKind::LoneSurrogate, start)),
                };
            }
            Some(_) => return self.err(ErrorKind::BadEscape),
        };
        self.i += 1;
        Ok(c)
    }

    /// The `\uXXXX` that must follow a high surrogate, and the character
    /// the pair makes.
    fn low_surrogate(&mut self, high: u32, start: usize) -> Result<char, Error> {
        for want in [b'\\', b'u'] {
            match self.b.get(self.i) {
                None => return self.err(ErrorKind::UnexpectedEnd),
                Some(&c) if c == want => self.i += 1,
                Some(_) => return Err(Error::at(ErrorKind::LoneSurrogate, start)),
            }
        }
        let low = self.hex4()?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(Error::at(ErrorKind::LoneSurrogate, start));
        }
        let c = 0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00);
        char::from_u32(c).ok_or(Error::at(ErrorKind::LoneSurrogate, start))
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let mut n = 0u32;
        for _ in 0..4 {
            let d = match self.b.get(self.i) {
                None => return self.err(ErrorKind::UnexpectedEnd),
                Some(&c) => match (c as char).to_digit(16) {
                    Some(d) => d,
                    None => return self.err(ErrorKind::BadEscape),
                },
            };
            n = n * 16 + d;
            self.i += 1;
        }
        Ok(n)
    }
}

struct Writer {
    out: String,
    size: usize,
    depth: usize,
    elements: usize,
    count: usize,
}

impl Writer {
    fn push(&mut self, s: &str) -> Result<(), Error> {
        self.out.push_str(s);
        self.fits()
    }

    fn fits(&self) -> Result<(), Error> {
        if self.out.len() > self.size {
            return Err(Error::at(ErrorKind::TooLarge, self.size));
        }
        Ok(())
    }

    fn err<T>(&self, kind: ErrorKind) -> Result<T, Error> {
        Err(Error::at(kind, self.out.len()))
    }

    /// Mirrors [`Parser::value`]: the same depth and element counts, so
    /// what it writes the parser reads. Recursion stops at the depth limit.
    fn value(&mut self, v: &Value, depth: usize) -> Result<(), Error> {
        self.count += 1;
        if self.count > self.elements {
            return self.err(ErrorKind::TooManyElements);
        }
        match v {
            Value::Null => self.push("null"),
            Value::Bool(true) => self.push("true"),
            Value::Bool(false) => self.push("false"),
            Value::Number(n) => self.push(&n.text),
            Value::String(s) => self.string(s),
            Value::Array(_) | Value::Object(_) if depth >= self.depth => self.err(ErrorKind::TooDeep),
            Value::Array(items) => {
                self.push("[")?;
                for (k, item) in items.iter().enumerate() {
                    if k > 0 {
                        self.push(",")?;
                    }
                    self.value(item, depth + 1)?;
                }
                self.push("]")
            }
            Value::Object(members) => {
                self.push("{")?;
                for (k, (key, item)) in members.iter().enumerate() {
                    if k > 0 {
                        self.push(",")?;
                    }
                    self.string(key)?;
                    self.push(":")?;
                    self.value(item, depth + 1)?;
                }
                self.push("}")
            }
        }
    }

    /// A string, quoted, escaping only `"`, `\` and control characters.
    /// It checks the size as it goes, so a long string stops early.
    fn string(&mut self, s: &str) -> Result<(), Error> {
        self.push("\"")?;
        for c in s.chars() {
            match c {
                '"' => self.out.push_str("\\\""),
                '\\' => self.out.push_str("\\\\"),
                '\n' => self.out.push_str("\\n"),
                '\r' => self.out.push_str("\\r"),
                '\t' => self.out.push_str("\\t"),
                '\u{8}' => self.out.push_str("\\b"),
                '\u{c}' => self.out.push_str("\\f"),
                c if (c as u32) < 0x20 => {
                    let hex = format!("\\u{:04x}", c as u32);
                    self.out.push_str(&hex);
                }
                c => self.out.push(c),
            }
            self.fits()?;
        }
        self.push("\"")
    }
}

impl Wire for Value {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(input: &[u8]) -> Result<Self, Error> {
        parse(input)
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(self.write()?.as_bytes());
        Ok(())
    }
}

/// Reads consecutive JSON values without holding input bytes.
///
/// Whitespace is skipped. Scalars end at a delimiter or EOF. Partial
/// values return [`Step::Need`], including at EOF. Syntax and limit errors
/// end the stream. Error offsets count from the start of the stream.
/// Capacity is the clamped size limit plus one delimiter or overflow byte.
/// Use [`codec::Stream`](super::codec::Stream) for bounded input and one-time errors.
///
/// ```
/// use fictionet::stdlib::{codec::{Stream, finish, pump}, json::{Value, Values}};
///
/// let mut stream = Stream::new(Values::new());
/// let mut values = Vec::new();
/// pump(&mut stream, b"true ", |value| values.push(value))?;
/// pump(&mut stream, b"null", |value| values.push(value))?;
/// finish(&mut stream, |value| values.push(value))?;
/// assert_eq!(values, vec![Value::Bool(true), Value::Null]);
/// # Ok::<(), fictionet::stdlib::codec::Fail<fictionet::stdlib::json::Error>>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct Values {
    limits: Limits,
    pos: usize,
    scan: Scan,
    consumed: usize,
}

impl Values {
    /// Reads values within the default [`Limits`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads values within `limits`, clamped to the module's named caps.
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    fn error(&self, kind: ErrorKind, offset: usize) -> Error {
        Error::at(kind, self.consumed.saturating_add(offset))
    }

    fn value(&mut self, input: &[u8], end: usize, eof: bool) -> Result<Step<Value>, Error> {
        let bytes = input.get(..end).unwrap_or_default();
        let mut result = parse_with(bytes, &self.limits);
        if let Err(e) = result
            && self.scan == Scan::Scalar
            && e.kind == ErrorKind::UnexpectedEnd
            && let Some(with_next) = input.get(..=end)
            && let Err(e) = parse_with(with_next, &self.limits)
        {
            // A delimiter interrupted the scalar. Name it as Decoder does.
            result = Err(e);
        }
        let value = match result {
            Ok(value) => value,
            Err(e) => {
                if eof
                    && self.scan == Scan::Scalar
                    && matches!(e.kind, ErrorKind::UnexpectedEnd | ErrorKind::BadNumber)
                    && scalar_prefix(bytes)
                {
                    return Ok(Step::Need);
                }
                return Err(self.error(e.kind, e.offset));
            }
        };
        self.pos = 0;
        self.scan = Scan::Idle;
        self.consumed = self.consumed.saturating_add(end);
        Ok(Step::Item(value, end))
    }
}

// A scalar prefix that could become valid with more input.
fn scalar_prefix(bytes: &[u8]) -> bool {
    if [b"true".as_slice(), b"false", b"null"]
        .iter()
        .any(|word| word.starts_with(bytes))
    {
        return true;
    }
    if bytes.len() >= MAX_NUMBER_LEN {
        return false;
    }
    let mut number = bytes.to_vec();
    number.push(b'0');
    matches!(parse(&number), Ok(Value::Number(_)))
}

impl Decode for Values {
    type Item = Value;
    type Error = Error;
    const NAME: &'static str = "JSON";

    fn capacity(&self) -> usize {
        self.limits.size().saturating_add(1)
    }

    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Value>, Error> {
        if self.scan == Scan::Idle {
            let whitespace = input.iter().take_while(|b| is_ws(**b)).count();
            if whitespace > 0 {
                self.consumed = self.consumed.saturating_add(whitespace);
                return Ok(Step::Skip(whitespace));
            }
        }
        while let Some(&c) = input.get(self.pos) {
            let mut end = None;
            match &mut self.scan {
                Scan::Idle => {
                    self.scan = match c {
                        b'{' | b'[' => Scan::Container {
                            depth: 1,
                            in_string: false,
                            escape: false,
                        },
                        b'"' => Scan::Str { escape: false },
                        c if is_scalar_byte(c) => Scan::Scalar,
                        _ => return self.value(input, 1, false),
                    };
                    if matches!(self.scan, Scan::Container { .. }) && self.limits.depth() == 0 {
                        return Err(self.error(ErrorKind::TooDeep, 0));
                    }
                }
                Scan::Container {
                    depth,
                    in_string,
                    escape,
                } => {
                    if *in_string {
                        if *escape {
                            *escape = false;
                        } else if c == b'\\' {
                            *escape = true;
                        } else if c == b'"' {
                            *in_string = false;
                        }
                    } else {
                        match c {
                            b'"' => *in_string = true,
                            b'{' | b'[' => {
                                *depth = depth.saturating_add(1);
                                if *depth > self.limits.depth() {
                                    // Report an earlier syntax error, as Decoder does.
                                    let prefix = input.get(..=self.pos).unwrap_or_default();
                                    let e = parse_with(prefix, &self.limits)
                                        .err()
                                        .unwrap_or(Error::at(ErrorKind::TooDeep, self.pos));
                                    return Err(self.error(e.kind, e.offset));
                                }
                            }
                            b'}' | b']' => {
                                *depth = depth.saturating_sub(1);
                                if *depth == 0 {
                                    end = Some(self.pos.saturating_add(1));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Scan::Str { escape } => {
                    if *escape {
                        *escape = false;
                    } else if c == b'\\' {
                        *escape = true;
                    } else if c == b'"' {
                        end = Some(self.pos.saturating_add(1));
                    }
                }
                Scan::Scalar => {
                    if !is_scalar_byte(c) {
                        return self.value(input, self.pos, false);
                    }
                }
            }
            // Container depth takes precedence, as in Decoder. A scalar
            // at the size limit may already have ended before this byte.
            if self.pos >= self.limits.size() {
                return Err(self.error(ErrorKind::TooLarge, self.limits.size()));
            }
            self.pos = self.pos.saturating_add(1);
            if let Some(end) = end {
                return self.value(input, end, false);
            }
        }
        if eof && self.scan == Scan::Scalar {
            return self.value(input, self.pos, true);
        }
        Ok(Step::Need)
    }
}

/// Splits a byte stream into JSON values, for protocols that send one
/// JSON text after another on a connection, such as JSON-RPC over TCP.
/// Feed it the bytes in order and take values out until it has none.
/// Whitespace between values is skipped, and values need none between
/// them, so `{}{}` is two values.
///
/// It does not look at line breaks. A protocol that frames each value as
/// one line (JSON Lines, NDJSON) should split the stream at `\n` and
/// [`parse`] each line, so that a value spread over two lines, or two
/// values on one line, is refused.
///
/// A value ends at its closing bracket or quote. A top-level number or
/// literal (`12`, `true`) ends at the first byte that cannot be part of
/// it, so one at the very end of what has come waits for one more byte,
/// or for [`Decoder::finish`] to say the stream has ended.
#[derive(Debug, Default)]
#[deprecated(note = "use codec::Stream with json::Values")]
pub struct Decoder {
    limits: Limits,
    buf: Vec<u8>,
    /// Where the unread bytes start in `buf`. Read bytes are dropped from
    /// the front only when the decoder runs out, so one large feed of
    /// many values is read in linear time.
    start: usize,
    /// The stream offset of `buf[start]`, to give errors stream offsets.
    consumed: usize,
    /// How much of the unread bytes has been scanned.
    pos: usize,
    scan: Scan,
    failed: Option<Error>,
    /// Whether [`Decoder::finish`] said no more bytes will come.
    ended: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Scan {
    /// Between values.
    #[default]
    Idle,
    /// Inside an array or object.
    Container { depth: usize, in_string: bool, escape: bool },
    /// Inside a top-level string.
    Str { escape: bool },
    /// Inside a top-level number or literal.
    Scalar,
}

fn is_scalar_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')
}

#[allow(deprecated)] // Preserve the compatibility API.
impl Decoder {
    /// A decoder with the default [`Limits`].
    pub fn new() -> Decoder {
        Decoder::default()
    }

    /// A decoder that holds each value to `limits`.
    pub fn with_limits(limits: Limits) -> Decoder {
        Decoder { limits, ..Decoder::default() }
    }

    /// Adds bytes read from the connection. After an error, or after
    /// [`Decoder::finish`], the stream cannot be read any further, and
    /// they are dropped.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_some() || self.ended {
            return;
        }
        // Drop the bytes already read once they are at least as many as
        // the unread ones, so moving the rest costs no more than reading
        // them did.
        if self.start > 0 && self.start >= self.buf.len() - self.start {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Says the stream has ended: no more bytes will come. After it,
    /// [`Decoder::next_value`] gives the values still held, a number or
    /// literal at the very end included, then an
    /// [`ErrorKind::UnexpectedEnd`] error if the stream stopped in the
    /// middle of a value (or the error parsing those bytes finds first),
    /// or `None` if it stopped between values.
    pub fn finish(&mut self) {
        self.ended = true;
    }

    /// The next whole value, if one has come. It returns `None` when it
    /// needs more bytes, or after [`Decoder::finish`] when the stream has
    /// ended cleanly, and keeps returning the same error once the stream
    /// has broken. Error offsets count from the start of the stream.
    ///
    /// The decoder holds the bytes fed and not yet read. Once
    /// `next_value` has returned `None`, that is at most one unfinished
    /// value, which the size limit caps, and bytes already read are
    /// dropped by the next [`Decoder::feed`].
    pub fn next_value(&mut self) -> Option<Result<Value, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        let size = self.limits.size();
        let max_depth = self.limits.depth();
        loop {
            let Some(&c) = self.buf.get(self.start.saturating_add(self.pos)) else {
                if !self.ended || self.scan == Scan::Idle {
                    if self.scan == Scan::Idle {
                        self.take(self.pos);
                        self.pos = 0;
                    }
                    self.buf.drain(..self.start);
                    self.start = 0;
                    // Give back the room a large feed took.
                    if self.buf.capacity() > size.saturating_mul(2).max(4096) {
                        self.buf.shrink_to(self.buf.len());
                    }
                    return None;
                }
                // The stream has ended inside a value. Parsing what came
                // finds the end, or an earlier error.
                return Some(self.end_value(self.pos));
            };
            let mut end = None;
            match &mut self.scan {
                Scan::Idle => {
                    if is_ws(c) {
                        self.pos += 1;
                        continue;
                    }
                    self.take(self.pos);
                    self.pos = 1;
                    match c {
                        b'{' | b'[' => {
                            self.scan = Scan::Container { depth: 1, in_string: false, escape: false };
                            if max_depth == 0 {
                                return Some(self.fail(ErrorKind::TooDeep, 0));
                            }
                        }
                        b'"' => self.scan = Scan::Str { escape: false },
                        c if is_scalar_byte(c) => self.scan = Scan::Scalar,
                        _ => end = Some(1),
                    }
                }
                Scan::Container { depth, in_string, escape } => {
                    if *in_string {
                        if *escape {
                            *escape = false;
                        } else if c == b'\\' {
                            *escape = true;
                        } else if c == b'"' {
                            *in_string = false;
                        }
                    } else {
                        match c {
                            b'"' => *in_string = true,
                            b'{' | b'[' => {
                                *depth += 1;
                                if *depth > max_depth {
                                    // An earlier byte may already break the
                                    // value. Report what parsing the same
                                    // bytes says, as for every other error.
                                    let at = self.pos;
                                    let prefix = &self.buf[self.start..=self.start + at];
                                    let e = parse_with(prefix, &self.limits).err().unwrap_or(Error::at(ErrorKind::TooDeep, at));
                                    return Some(self.fail(e.kind, e.offset));
                                }
                            }
                            b'}' | b']' => {
                                *depth = depth.saturating_sub(1);
                                if *depth == 0 {
                                    end = Some(self.pos + 1);
                                }
                            }
                            _ => {}
                        }
                    }
                    self.pos += 1;
                }
                Scan::Str { escape } => {
                    if *escape {
                        *escape = false;
                    } else if c == b'\\' {
                        *escape = true;
                    } else if c == b'"' {
                        end = Some(self.pos + 1);
                    }
                    self.pos += 1;
                }
                Scan::Scalar => {
                    if is_scalar_byte(c) {
                        self.pos += 1;
                    } else {
                        end = Some(self.pos);
                    }
                }
            }
            if let Some(end) = end {
                return Some(self.end_value(end));
            }
            if self.pos > size {
                return Some(self.fail(ErrorKind::TooLarge, size));
            }
        }
    }

    /// Parses the value in the first `end` unread bytes and moves past it.
    fn end_value(&mut self, end: usize) -> Result<Value, Error> {
        let stop = self.start.saturating_add(end).min(self.buf.len());
        let value = &self.buf[self.start..stop];
        let mut result = parse_with(value, &self.limits);
        if let Err(e) = result
            && self.scan == Scan::Scalar
            && e.kind == ErrorKind::UnexpectedEnd
            && let Some(with_next) = self.buf.get(self.start..=stop)
        {
            // The stream did not end: the byte after the scalar broke
            // it. Name that byte, as parsing the scalar and the byte
            // together does.
            if let Err(e) = parse_with(with_next, &self.limits) {
                result = Err(e);
            }
        }
        let base = self.consumed;
        self.take(end);
        self.scan = Scan::Idle;
        self.pos = 0;
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                let e = Error::at(e.kind, base.saturating_add(e.offset));
                self.failed = Some(e);
                self.buf = Vec::new();
                self.start = 0;
                Err(e)
            }
        }
    }

    /// How many bytes are held, waiting for the rest of a value.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }

    /// Marks the first `n` unread bytes as read.
    fn take(&mut self, n: usize) {
        self.start = self.start.saturating_add(n).min(self.buf.len());
        self.consumed = self.consumed.saturating_add(n);
    }

    /// Breaks the stream with an error at `at`, an offset into `buf`.
    fn fail(&mut self, kind: ErrorKind, at: usize) -> Result<Value, Error> {
        let e = Error::at(kind, self.consumed.saturating_add(at));
        self.failed = Some(e);
        self.buf = Vec::new();
        self.start = 0;
        Err(e)
    }
}

#[cfg(test)]
#[allow(deprecated)] // These tests cover the compatibility API.
mod tests {
    use super::*;

    fn s(v: &str) -> Value {
        Value::from(v)
    }

    fn n(text: &str) -> Value {
        Value::Number(Number::from_text(text).unwrap())
    }

    fn err(input: &[u8]) -> (ErrorKind, usize) {
        let e = parse(input).unwrap_err();
        (e.kind, e.offset)
    }

    fn round_trip(v: &Value) {
        let text = v.write().unwrap();
        assert_eq!(&parse(text.as_bytes()).unwrap(), v, "{text}");
    }

    // RFC 8259, section 13.

    #[test]
    fn rfc_object_example() {
        let text = br#"
            {
              "Image": {
                  "Width":  800,
                  "Height": 600,
                  "Title":  "View from 15th Floor",
                  "Thumbnail": {
                      "Url":    "http://www.example.com/image/481989943",
                      "Height": 125,
                      "Width":  100
                  },
                  "Animated" : false,
                  "IDs": [116, 943, 234, 38793]
                }
            }"#;
        let v = parse(text).unwrap();
        let image = v.get("Image").unwrap();
        assert_eq!(image.get("Width").and_then(Value::as_number).and_then(Number::as_u64), Some(800));
        assert_eq!(image.get("Title").and_then(Value::as_str), Some("View from 15th Floor"));
        assert_eq!(image.get("Animated").and_then(Value::as_bool), Some(false));
        let thumb = image.get("Thumbnail").unwrap();
        assert_eq!(thumb.get("Url").and_then(Value::as_str), Some("http://www.example.com/image/481989943"));
        let ids: Vec<i64> = image.get("IDs").unwrap().as_array().unwrap().iter().map(|v| v.as_number().unwrap().as_i64().unwrap()).collect();
        assert_eq!(ids, [116, 943, 234, 38793]);
        let keys: Vec<&str> = image.as_object().unwrap().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["Width", "Height", "Title", "Thumbnail", "Animated", "IDs"]);
        round_trip(&v);
    }

    #[test]
    fn rfc_array_example() {
        let text = br#"
            [
              {
                 "precision": "zip",
                 "Latitude":  37.7668,
                 "Longitude": -122.3959,
                 "Address":   "",
                 "City":      "SAN FRANCISCO",
                 "State":     "CA",
                 "Zip":       "94107",
                 "Country":   "US"
              },
              {
                 "precision": "zip",
                 "Latitude":  37.371991,
                 "Longitude": -122.026020,
                 "Address":   "",
                 "City":      "SUNNYVALE",
                 "State":     "CA",
                 "Zip":       "94085",
                 "Country":   "US"
              }
            ]"#;
        let v = parse(text).unwrap();
        let items = v.as_array().unwrap();
        assert_eq!(items.len(), 2);
        let lon = items[1].get("Longitude").and_then(Value::as_number).unwrap();
        // The exact text stays, trailing zero included.
        assert_eq!(lon.text(), "-122.026020");
        assert_eq!(lon.as_f64(), -122.02602);
        assert_eq!(items[0].get("Address").and_then(Value::as_str), Some(""));
        round_trip(&v);
    }

    #[test]
    fn rfc_scalar_texts() {
        assert_eq!(parse(b"\"Hello world!\"").unwrap(), s("Hello world!"));
        assert_eq!(parse(b"42").unwrap(), n("42"));
        assert_eq!(parse(b"true").unwrap(), Value::Bool(true));
        assert_eq!(parse(b"false").unwrap(), Value::Bool(false));
        assert_eq!(parse(b" \t\r\nnull \n").unwrap(), Value::Null);
    }

    #[test]
    fn numbers() {
        for good in ["0", "-0", "1", "-1", "10", "1.5", "0.25", "-0.0", "1e5", "1E5", "1e+5", "1e-5", "2.5E-03", "123456789012345678901234567890"] {
            let v = parse(good.as_bytes()).unwrap();
            assert_eq!(v.as_number().unwrap().text(), good);
            assert_eq!(v.write().unwrap(), good);
            assert!(Number::from_text(good).is_some());
        }
        for bad in ["-", "01", "-01", "00", "1.", ".5", "+1", "1e", "1e+", "1.e5", "0x10", "Infinity", "NaN", "-Infinity", " 1", "1 ", "1.5.5", ""] {
            assert!(parse(bad.as_bytes()).is_err() || bad.trim() != bad, "{bad}");
            assert!(Number::from_text(bad).is_none(), "{bad}");
        }
        let big = Number::from_text("1e400").unwrap();
        assert!(big.as_f64().is_infinite());
        assert_eq!(big.as_i64(), None);
        assert_eq!(Number::from_text("9223372036854775807").unwrap().as_i64(), Some(i64::MAX));
        assert_eq!(Number::from_text("9223372036854775808").unwrap().as_i64(), None);
        assert_eq!(Number::from_text("9223372036854775808").unwrap().as_u64(), Some(1 << 63));
        assert_eq!(Number::from_text("-1").unwrap().as_u64(), None);
        assert_eq!(Number::from_text("1.0").unwrap().as_i64(), None);
        assert_eq!(Number::from_text("1e2").unwrap().as_f64(), 100.0);
        assert_ne!(Number::from_text("1.0"), Number::from_text("1"));
        assert_eq!(Number::from_i64(i64::MIN).text(), "-9223372036854775808");
        assert_eq!(Number::from_u64(u64::MAX).text(), "18446744073709551615");
        for f in [0.0, -0.0, 1.5, -2.25, 1e300, 5e-324, f64::MAX, f64::MIN_POSITIVE, 0.1, 123456.789] {
            let num = Number::from_f64(f).unwrap();
            assert_eq!(num.as_f64(), f, "{}", num.text());
            assert!(num.text().len() <= 32, "{}", num.text());
        }
        assert_eq!(Number::from_f64(f64::NAN), None);
        assert_eq!(Number::from_f64(f64::INFINITY), None);
        assert_eq!(Number::from_text(&"1".repeat(MAX_NUMBER_LEN)).unwrap().text().len(), MAX_NUMBER_LEN);
        assert!(Number::from_text(&"1".repeat(MAX_NUMBER_LEN + 1)).is_none());
    }

    #[test]
    fn strings_and_escapes() {
        let v = parse(br#""a\"b\\c\/d\be\ff\ng\rh\ti\u0041\u00e9\u20ac""#).unwrap();
        assert_eq!(v, s("a\"b\\c/d\u{8}e\u{c}f\ng\rh\tiAé€"));
        // A surrogate pair, upper and lower case hex.
        assert_eq!(parse(br#""\ud83d\ude00""#).unwrap(), s("😀"));
        assert_eq!(parse(br#""\uD834\uDD1E""#).unwrap(), s("𝄞"));
        // Raw UTF-8 passes through.
        assert_eq!(parse("\"日本 😀\"".as_bytes()).unwrap(), s("日本 😀"));
        // U+0000 is allowed as an escape.
        assert_eq!(parse(br#""\u0000""#).unwrap(), s("\0"));
        // The writer escapes only what it must.
        let w = s("q\"b\\/\n\u{1}\u{7f}é😀").write().unwrap();
        assert_eq!(w, "\"q\\\"b\\\\/\\n\\u0001\u{7f}é😀\"");
        round_trip(&s("q\"b\\/\n\u{1}\u{1f}\u{7f}é😀\u{2028}"));
        for c in 0..0x20u32 {
            round_trip(&Value::String(char::from_u32(c).unwrap().to_string()));
        }
    }

    #[test]
    fn duplicate_keys_kept_in_order() {
        let v = parse(br#"{"a":1,"b":2,"a":3}"#).unwrap();
        let members = v.as_object().unwrap();
        assert_eq!(members.len(), 3);
        assert_eq!(members[2], ("a".to_string(), n("3")));
        assert_eq!(v.get("a"), Some(&n("1")));
        assert_eq!(v.get("c"), None);
        assert_eq!(v.write().unwrap(), r#"{"a":1,"b":2,"a":3}"#);
    }

    #[test]
    fn each_error() {
        assert_eq!(err(b""), (ErrorKind::UnexpectedEnd, 0));
        assert_eq!(err(b"   "), (ErrorKind::UnexpectedEnd, 3));
        assert_eq!(err(b"[1,2"), (ErrorKind::UnexpectedEnd, 4));
        assert_eq!(err(b"[1,]"), (ErrorKind::UnexpectedByte(b']'), 3));
        assert_eq!(err(b"{\"a\":1,}"), (ErrorKind::UnexpectedByte(b'}'), 7));
        assert_eq!(err(b"{'a':1}"), (ErrorKind::UnexpectedByte(b'\''), 1));
        assert_eq!(err(b"{\"a\" 1}"), (ErrorKind::UnexpectedByte(b'1'), 5));
        assert_eq!(err(b"{1:2}"), (ErrorKind::UnexpectedByte(b'1'), 1));
        assert_eq!(err(b"[1 2]"), (ErrorKind::UnexpectedByte(b'2'), 3));
        assert_eq!(err(b"tru"), (ErrorKind::UnexpectedEnd, 3));
        assert_eq!(err(b"trux"), (ErrorKind::UnexpectedByte(b'x'), 3));
        assert_eq!(err(b"nul"), (ErrorKind::UnexpectedEnd, 3));
        assert_eq!(err(b"[1]/*c*/"), (ErrorKind::TrailingBytes, 3));
        assert_eq!(err(b"1 2"), (ErrorKind::TrailingBytes, 2));
        assert_eq!(err(b"\xef\xbb\xbf1"), (ErrorKind::UnexpectedByte(0xef), 0));
        assert_eq!(err(b"\x0c1"), (ErrorKind::UnexpectedByte(0x0c), 0));
        assert_eq!(err(b"\"a\xffb\""), (ErrorKind::InvalidUtf8, 2));
        assert_eq!(err(b"\"ab\xc3\""), (ErrorKind::InvalidUtf8, 3));
        assert_eq!(err(b"\"\xed\xa0\x80\""), (ErrorKind::InvalidUtf8, 1));
        assert_eq!(err(b"01"), (ErrorKind::BadNumber, 1));
        assert_eq!(err(b"1.x"), (ErrorKind::BadNumber, 2));
        assert_eq!(err(b"-a"), (ErrorKind::BadNumber, 1));
        assert_eq!(err(b"1e"), (ErrorKind::UnexpectedEnd, 2));
        assert_eq!(err("1".repeat(MAX_NUMBER_LEN + 1).as_bytes()), (ErrorKind::NumberTooLong, 0));
        assert_eq!(err(br#""\x""#), (ErrorKind::BadEscape, 2));
        assert_eq!(err(br#""\u12g4""#), (ErrorKind::BadEscape, 5));
        assert_eq!(err(br#""\ud800""#), (ErrorKind::LoneSurrogate, 1));
        assert_eq!(err(br#""ab\udc00""#), (ErrorKind::LoneSurrogate, 3));
        assert_eq!(err(br#""\ud800\n""#), (ErrorKind::LoneSurrogate, 1));
        assert_eq!(err(br#""\ud800\u0041""#), (ErrorKind::LoneSurrogate, 1));
        assert_eq!(err(br#""\ud800\ud800""#), (ErrorKind::LoneSurrogate, 1));
        assert_eq!(err(b"\"a\tb\""), (ErrorKind::ControlCharacter, 2));
        assert_eq!(err(b"\"a\nb\""), (ErrorKind::ControlCharacter, 2));
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(err(deep.as_bytes()), (ErrorKind::TooDeep, MAX_DEPTH));
        let big = vec![b' '; MAX_SIZE + 1];
        assert_eq!(err(&big), (ErrorKind::TooLarge, MAX_SIZE));
        let many = format!("[{}0]", "0,".repeat(MAX_ELEMENTS));
        assert_eq!(parse(many.as_bytes()).unwrap_err().kind, ErrorKind::TooManyElements);
        // Every kind prints.
        assert_eq!(Error::at(ErrorKind::BadEscape, 4).to_string(), "an unknown escape at byte 4");
    }

    #[test]
    fn limits() {
        let at = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        let v = parse(at.as_bytes()).unwrap();
        round_trip(&v);
        let tight = Limits { depth: 2, size: 20, elements: 4 };
        assert!(parse_with(b"[[1]]", &tight).is_ok());
        assert_eq!(parse_with(b"[[[]]]", &tight).unwrap_err(), Error::at(ErrorKind::TooDeep, 2));
        assert_eq!(parse_with(b"{\"a\":{\"b\":{}}}", &tight).unwrap_err().kind, ErrorKind::TooDeep);
        assert_eq!(parse_with(b"[1,2,3,4]", &tight).unwrap_err(), Error::at(ErrorKind::TooManyElements, 7));
        assert!(parse_with(b"[1,2,3]", &tight).is_ok());
        assert_eq!(parse_with(&[b' '; 21], &tight).unwrap_err().kind, ErrorKind::TooLarge);
        let scalars_only = Limits { depth: 0, ..Limits::default() };
        assert!(parse_with(b"1", &scalars_only).is_ok());
        assert_eq!(parse_with(b"[]", &scalars_only).unwrap_err().kind, ErrorKind::TooDeep);
        // Limits cannot go past the constants.
        let loose = Limits { depth: usize::MAX, size: usize::MAX, elements: usize::MAX };
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(parse_with(deep.as_bytes(), &loose).unwrap_err().kind, ErrorKind::TooDeep);
    }

    #[test]
    fn writer_refuses_what_the_parser_would() {
        let mut deep = Value::Null;
        for _ in 0..MAX_DEPTH + 1 {
            deep = Value::Array(vec![deep]);
        }
        assert_eq!(deep.write().unwrap_err().kind, ErrorKind::TooDeep);
        let Value::Array(mut inner) = deep else { panic!() };
        round_trip(&inner.pop().unwrap());
        let big = Value::String("x".repeat(MAX_SIZE));
        assert_eq!(big.write().unwrap_err().kind, ErrorKind::TooLarge);
        assert!(Value::String("x".repeat(MAX_SIZE - 2)).write().is_ok());
        let escapes = Value::String("\u{1}".repeat(MAX_SIZE / 6 + 1));
        assert_eq!(escapes.write().unwrap_err().kind, ErrorKind::TooLarge);
        let many = Value::Array(vec![Value::Null; MAX_ELEMENTS]);
        assert_eq!(many.write().unwrap_err().kind, ErrorKind::TooManyElements);
        let ok = Value::Array(vec![Value::Null; MAX_ELEMENTS - 1]);
        round_trip(&ok);
        let tight = Limits { depth: 1, size: 10, elements: 3 };
        assert_eq!(Value::Array(vec![Value::Array(vec![])]).write_with(&tight).unwrap_err(), Error::at(ErrorKind::TooDeep, 1));
        assert_eq!(s("0123456789").write_with(&tight).unwrap_err().kind, ErrorKind::TooLarge);
        assert_eq!(Value::Array(vec![true.into(), false.into(), Value::Null]).write_with(&Limits { size: 100, ..tight }).unwrap_err().kind, ErrorKind::TooManyElements);
    }

    #[test]
    fn round_trips() {
        let v = Value::Object(vec![
            ("".into(), Value::Null),
            ("n".into(), Value::from(-7i64)),
            ("u".into(), Value::from(u64::MAX)),
            ("f".into(), Value::from(Number::from_f64(-1.25e-9).unwrap())),
            ("s".into(), s("tab\there \"quoted\" \\ é 😀")),
            ("a".into(), Value::Array(vec![Value::Array(vec![]), Value::Object(vec![]), true.into()])),
            ("n".into(), Value::from("again")),
        ]);
        round_trip(&v);
        let text = v.write().unwrap();
        assert_eq!(parse(text.as_bytes()).unwrap().write().unwrap(), text);
        // Whitespace anywhere it may go.
        let spaced = b" { \"a\" : [ 1 , { } , [ ] ] , \"b\" : null } ";
        assert_eq!(parse(spaced).unwrap().write().unwrap(), r#"{"a":[1,{},[]],"b":null}"#);
    }

    #[test]
    fn every_truncated_prefix() {
        let docs: [&[u8]; 6] = [
            br#"{"a":[1,2.5e-3,true,false,null],"b":{"c":"d\u00e9\ud83d\ude00\n"}}"#,
            br#"[ "x" , -0.5 , {} , [] ]"#,
            "[\"日本😀\"]".as_bytes(),
            br#""\ud83d\ude00\\""#,
            b"{\"k\" : \"v\" }",
            b"[[[[]]]]",
        ];
        for doc in docs {
            assert!(parse(doc).is_ok());
            for cut in 0..doc.len() {
                let e = parse(&doc[..cut]).unwrap_err();
                assert_eq!(e.kind, ErrorKind::UnexpectedEnd, "{:?}", String::from_utf8_lossy(&doc[..cut]));
                assert!(e.offset <= cut);
                let mut d = Decoder::new();
                d.feed(&doc[..cut]);
                assert_eq!(d.next_value(), None);
                // Once the stream ends, the decoder reports what parsing
                // reports, or nothing when no value had started.
                d.finish();
                let want = if doc[..cut].iter().all(|&c| is_ws(c)) { None } else { Some(Err(e)) };
                assert_eq!(d.next_value(), want, "{:?}", String::from_utf8_lossy(&doc[..cut]));
            }
        }
    }

    #[test]
    fn decoder_drops_bytes_it_has_read() {
        // One value per feed, taking one value each time and never asking
        // for the `None` after it. The read bytes must not pile up.
        let mut d = Decoder::new();
        for _ in 0..10_000 {
            d.feed(b"{}");
            assert_eq!(d.next_value(), Some(Ok(Value::Object(vec![]))));
            assert_eq!(d.buffered(), 0);
        }
        assert!(d.buf.len() <= 4, "{} bytes held", d.buf.len());
        // A large feed does not keep its room once it has been read.
        let mut d = Decoder::new();
        d.feed(&vec![b' '; 3 * MAX_SIZE]);
        assert_eq!(d.next_value(), None);
        assert!(d.buf.capacity() <= 2 * MAX_SIZE, "{} bytes of room kept", d.buf.capacity());
        d.feed(b"[1]");
        assert_eq!(d.next_value(), Some(Ok(parse(b"[1]").unwrap())));
    }

    #[test]
    fn decoder_finish_ends_the_stream() {
        // A number or literal at the very end of the stream.
        for text in ["42", "-1.5e3", "true", "false", "null", "0"] {
            let mut d = Decoder::new();
            d.feed(text.as_bytes());
            assert_eq!(d.next_value(), None);
            d.finish();
            assert_eq!(d.next_value(), Some(Ok(parse(text.as_bytes()).unwrap())), "{text}");
            assert_eq!(d.next_value(), None);
        }
        // A last line with no line break after it.
        let mut d = Decoder::new();
        d.feed(b"{\"a\":1}\n42");
        d.finish();
        assert_eq!(d.next_value(), Some(Ok(parse(b"{\"a\":1}").unwrap())));
        assert_eq!(d.next_value(), Some(Ok(n("42"))));
        assert_eq!(d.next_value(), None);
        // A value cut off by the end, with a stream offset.
        let cases: [(&[u8], Error); 6] = [
            (b"{\"a\":", Error::at(ErrorKind::UnexpectedEnd, 5)),
            (b"[1] [2,", Error::at(ErrorKind::UnexpectedEnd, 7)),
            (b" \"abc", Error::at(ErrorKind::UnexpectedEnd, 5)),
            (b"tru", Error::at(ErrorKind::UnexpectedEnd, 3)),
            (b"1e", Error::at(ErrorKind::UnexpectedEnd, 2)),
            (b"[x", Error::at(ErrorKind::UnexpectedByte(b'x'), 1)),
        ];
        for (input, want) in cases {
            for bytewise in [false, true] {
                let got = decode_finished(input, bytewise);
                assert_eq!(got.last(), Some(&Err(want)), "{:?}", String::from_utf8_lossy(input));
            }
        }
        // Bytes after the end are dropped, and the end stays.
        let mut d = Decoder::new();
        d.feed(b" ");
        d.finish();
        d.feed(b"1 ");
        assert_eq!(d.next_value(), None);
        assert_eq!(d.buffered(), 0);
    }

    #[test]
    fn decoder_does_not_frame_lines() {
        // The decoder splits concatenated JSON texts, not lines. Two
        // values on one line are two values, and one value may span
        // lines. A JSON Lines reader splits at `\n` and parses each line.
        let mut d = Decoder::new();
        d.feed(b"{}{}\n{\n\"a\":1\n}\n");
        assert_eq!(d.next_value(), Some(Ok(Value::Object(vec![]))));
        assert_eq!(d.next_value(), Some(Ok(Value::Object(vec![]))));
        assert_eq!(d.next_value(), Some(Ok(parse(b"{\"a\":1}").unwrap())));
        assert_eq!(d.next_value(), None);
    }

    #[test]
    fn decoder_splits_a_stream() {
        let stream = b" {\"id\":1} [2]\n\"three\" 4 true null {\"id\":5}\n";
        let want = [
            parse(b"{\"id\":1}").unwrap(),
            parse(b"[2]").unwrap(),
            s("three"),
            n("4"),
            Value::Bool(true),
            Value::Null,
            parse(b"{\"id\":5}").unwrap(),
        ];
        // All at once, then a byte at a time.
        let mut d = Decoder::new();
        d.feed(stream);
        let mut got = Vec::new();
        while let Some(v) = d.next_value() {
            got.push(v.unwrap());
        }
        assert_eq!(got, want);
        assert_eq!(d.buffered(), 0);
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for b in stream {
            d.feed(std::slice::from_ref(b));
            while let Some(v) = d.next_value() {
                got.push(v.unwrap());
            }
        }
        assert_eq!(got, want);
        // A number at the end waits for the byte after it.
        let mut d = Decoder::new();
        d.feed(b"12");
        assert_eq!(d.next_value(), None);
        d.feed(b"3\n");
        assert_eq!(d.next_value(), Some(Ok(n("123"))));
        // Brackets inside strings do not count.
        d.feed(br#"["]\"[", {"}":"{"}]"#);
        assert_eq!(d.next_value(), Some(Ok(parse(br#"["]\"[", {"}":"{"}]"#).unwrap())));
        // An error has a stream offset, and stays.
        d.feed(b" [1,]");
        assert_eq!(d.next_value(), Some(Err(Error::at(ErrorKind::UnexpectedByte(b']'), 27))));
        d.feed(b"[1]");
        assert_eq!(d.next_value(), Some(Err(Error::at(ErrorKind::UnexpectedByte(b']'), 27))));
        assert_eq!(d.buffered(), 0);
        // A stray closing bracket.
        let mut d = Decoder::new();
        d.feed(b"]");
        assert_eq!(d.next_value(), Some(Err(Error::at(ErrorKind::UnexpectedByte(b']'), 0))));
    }

    #[test]
    fn decoder_limits() {
        let tight = Limits { depth: 2, size: 8, elements: 100 };
        let mut d = Decoder::with_limits(tight);
        d.feed(b"[[]] [[[");
        assert_eq!(d.next_value(), Some(Ok(parse(b"[[]]").unwrap())));
        assert_eq!(d.next_value(), Some(Err(Error::at(ErrorKind::TooDeep, 7))));
        // An unfinished value past the size limit.
        let mut d = Decoder::with_limits(tight);
        d.feed(b"  \"abcdefg");
        assert_eq!(d.next_value(), None);
        d.feed(b"h");
        assert_eq!(d.next_value(), Some(Err(Error::at(ErrorKind::TooLarge, 10))));
        // Whitespace between values is not held.
        let mut d = Decoder::new();
        d.feed(&[b' '; 1000]);
        assert_eq!(d.next_value(), None);
        assert_eq!(d.buffered(), 0);
        let mut d = Decoder::with_limits(Limits { depth: 0, ..Limits::default() });
        d.feed(b"1 {");
        assert_eq!(d.next_value(), Some(Ok(n("1"))));
        assert_eq!(d.next_value(), Some(Err(Error::at(ErrorKind::TooDeep, 2))));
    }

    #[test]
    fn decoder_too_deep_reports_an_earlier_error() {
        // `x` breaks the value before the nesting gets too deep, and
        // `parse` says so. The decoder must agree.
        let input = format!("[x{}", "[".repeat(MAX_DEPTH + 10));
        let want = parse(input.as_bytes()).unwrap_err();
        assert_eq!(want, Error::at(ErrorKind::UnexpectedByte(b'x'), 1));
        for bytewise in [false, true] {
            assert_eq!(decode_all(input.as_bytes(), bytewise), [Err(want)]);
        }
        // With nothing wrong before it, the depth is the error.
        let input = format!(" {}", "[".repeat(MAX_DEPTH + 1));
        for bytewise in [false, true] {
            assert_eq!(decode_all(input.as_bytes(), bytewise), [Err(Error::at(ErrorKind::TooDeep, MAX_DEPTH + 1))]);
        }
        let tight = Limits { depth: 2, size: 100, elements: 2 };
        let mut d = Decoder::with_limits(tight);
        d.feed(b"[1,2,[[");
        assert_eq!(d.next_value(), Some(Err(parse_with(b"[1,2,[[", &tight).unwrap_err())));
        assert_eq!(d.next_value().unwrap().unwrap_err().kind, ErrorKind::TooManyElements);
    }

    #[test]
    fn values_from_plain_rust() {
        // An integer literal is an i32, so `Value::from(3)` must build.
        assert_eq!(Value::from(3), n("3"));
        assert_eq!(Value::from(-3), n("-3"));
        assert_eq!(Value::from(7u32), n("7"));
        assert_eq!(Value::from(vec![Value::from(1), Value::Null]).write().unwrap(), "[1,null]");
        assert_eq!(Value::default(), Value::Null);
        let v = parse(b"[12, 1.5, -1, \"x\"]").unwrap();
        let items = v.as_array().unwrap();
        assert_eq!(items[0].as_i64(), Some(12));
        assert_eq!(items[0].as_u64(), Some(12));
        assert_eq!(items[1].as_i64(), None);
        assert_eq!(items[1].as_f64(), Some(1.5));
        assert_eq!(items[2].as_u64(), None);
        assert_eq!(items[3].as_f64(), None);
        // Values can key a hash map, and equal values hash the same.
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(v.clone()));
        assert!(!seen.insert(parse(b"[12,1.5,-1,\"x\"]").unwrap()));
    }

    #[test]
    fn negative_zero_is_a_u64() {
        // `-0` is zero, a non-negative integer, as `as_i64` agrees.
        assert_eq!(Number::from_text("-0").unwrap().as_i64(), Some(0));
        assert_eq!(Number::from_text("-0").unwrap().as_u64(), Some(0));
        assert_eq!(Number::from_text("-1").unwrap().as_u64(), None);
        assert_eq!(Number::from_text("-00").map(|n| n.as_u64()), None);
    }

    #[test]
    fn decoder_scalar_cut_by_a_byte_is_not_an_end() {
        // The stream did not end, so the error names the byte that broke
        // the value, as parsing the same bytes in one text would.
        let cases: [(&[u8], ErrorKind, usize); 5] = [
            (b"tru ", ErrorKind::UnexpectedByte(b' '), 3),
            (b"- ", ErrorKind::BadNumber, 1),
            (b"1e,", ErrorKind::BadNumber, 2),
            (b"1.[", ErrorKind::BadNumber, 2),
            (b"  nul\"", ErrorKind::UnexpectedByte(b'"'), 5),
        ];
        for (input, kind, offset) in cases {
            for bytewise in [false, true] {
                assert_eq!(decode_all(input, bytewise), [Err(Error::at(kind, offset))], "{:?}", String::from_utf8_lossy(input));
            }
        }
    }

    #[test]
    fn decoder_is_linear_in_one_large_feed() {
        // A million values in one feed, which takes a tenth of a second.
        // Shifting the buffer after each value made it take over ten.
        let stream = "0\n".repeat(MAX_SIZE);
        let start = std::time::Instant::now();
        let mut d = Decoder::new();
        d.feed(stream.as_bytes());
        let mut count = 0;
        while let Some(v) = d.next_value() {
            assert_eq!(v, Ok(n("0")));
            count += 1;
            assert_eq!(d.buffered(), stream.len() - 2 * count + 1);
        }
        assert_eq!(count, MAX_SIZE);
        assert_eq!(d.buffered(), 0);
        assert!(start.elapsed() < std::time::Duration::from_secs(3), "{:?}", start.elapsed());
    }

    /// A small deterministic generator, so the fuzz loop needs no crates.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
        fn below(&mut self, n: usize) -> usize {
            self.next() as usize % n.max(1)
        }
    }

    const PIECES: [&str; 32] = [
        "{", "}", "[", "]", ",", ":", " ", "\n", "\"", "\"a\"", "\"k\":", "\\", "\\u", "d83d", "\\ude00", "\\n", "0", "1", "-", ".", "e", "+", "12.5", "true", "false", "null", "tru", "é", "\u{1}", "x", "\"\\ud800\"", "9e999",
    ];

    fn random_input(r: &mut Lcg) -> Vec<u8> {
        let mut b = Vec::new();
        for _ in 0..r.below(40) {
            match r.below(10) {
                0 => b.push(r.next() as u8),
                _ => b.extend_from_slice(PIECES[r.below(PIECES.len())].as_bytes()),
            }
        }
        b
    }

    fn random_value(r: &mut Lcg, depth: usize) -> Value {
        match r.below(if depth > 4 { 4 } else { 6 }) {
            0 => Value::Null,
            1 => Value::Bool(r.next() & 1 == 1),
            2 => match r.below(3) {
                0 => Value::from(r.next() as i64 - (1 << 31)),
                1 => Value::from(Number::from_f64(f64::from_bits(u64::from(r.next()) << 32 | u64::from(r.next()))).unwrap_or(Number::from_i64(0))),
                _ => Value::from(Number::from_text(&format!("{}.{}e-{}", r.next(), r.next(), r.below(400))).unwrap()),
            },
            3 => Value::String((0..r.below(8)).filter_map(|_| char::from_u32(r.next() % 0x11000)).collect()),
            4 => Value::Array((0..r.below(5)).map(|_| random_value(r, depth + 1)).collect()),
            _ => Value::Object((0..r.below(5)).map(|_| (PIECES[r.below(PIECES.len())].to_string(), random_value(r, depth + 1))).collect()),
        }
    }

    fn decode_all(data: &[u8], bytewise: bool) -> Vec<Result<Value, Error>> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        let take = |d: &mut Decoder, out: &mut Vec<Result<Value, Error>>| {
            while let Some(v) = d.next_value() {
                let stop = v.is_err();
                out.push(v);
                if stop {
                    return true;
                }
            }
            false
        };
        if bytewise {
            for b in data {
                d.feed(std::slice::from_ref(b));
                if take(&mut d, &mut out) {
                    break;
                }
            }
        } else {
            d.feed(data);
            take(&mut d, &mut out);
        }
        out
    }

    /// Every value the decoder gives for `data` as a whole stream, ended
    /// with [`Decoder::finish`], up to and including its first error.
    fn decode_finished(data: &[u8], bytewise: bool) -> Vec<Result<Value, Error>> {
        let mut d = Decoder::new();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
        for chunk in chunks {
            d.feed(chunk);
            // Take at most one value per feed, so read bytes wait in the
            // buffer while more come.
            if let Some(v) = d.next_value() {
                let stop = v.is_err();
                out.push(v);
                if stop {
                    return out;
                }
            }
        }
        d.finish();
        while let Some(v) = d.next_value() {
            let stop = v.is_err();
            out.push(v);
            if stop {
                break;
            }
        }
        out
    }

    /// A whole JSON text, as a stream that then ends, gives just its value.
    fn stream_matches_parse(data: &[u8]) {
        let whole = decode_finished(data, false);
        assert_eq!(whole, decode_finished(data, true), "{:?}", String::from_utf8_lossy(data));
        if let Ok(v) = parse(data) {
            assert_eq!(whole, [Ok(v)], "{:?}", String::from_utf8_lossy(data));
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut r = Lcg(0x5eed_1234);
        let mut parsed = 0;
        for _ in 0..20_000 {
            let data = random_input(&mut r);
            if let Ok(v) = parse(&data) {
                parsed += 1;
                round_trip(&v);
            }
            assert_eq!(decode_all(&data, false), decode_all(&data, true));
            stream_matches_parse(&data);
            for v in decode_all(&data, false).into_iter().flatten() {
                round_trip(&v);
            }
        }
        assert!(parsed > 100, "only {parsed} parsed");
        // Built values, and valid texts with one byte changed or cut.
        for _ in 0..5_000 {
            let v = random_value(&mut r, 0);
            round_trip(&v);
            let mut text = v.write().unwrap().into_bytes();
            assert_eq!(decode_all(&text, false), decode_all(&text, true));
            stream_matches_parse(&text);
            if !text.is_empty() {
                let at = r.below(text.len());
                text[at] = r.next() as u8;
                if let Ok(w) = parse(&text) {
                    round_trip(&w);
                }
                let cut = r.below(text.len());
                let _ = parse(&text[..cut]);
                assert_eq!(decode_all(&text[..cut], false), decode_all(&text[..cut], true));
                stream_matches_parse(&text[..cut]);
                stream_matches_parse(&text);
            }
        }
    }
}
