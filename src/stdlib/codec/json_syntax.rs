//! JSON string and number tokens, independent of value trees.
//!
//! [`read_string`] decodes one quoted string. [`scan_number`] finds the end
//! of one number without converting it. Both take a starting byte offset and
//! report absolute offsets into the supplied slice. They skip no whitespace
//! and never change a caller's cursor. Advance it only after accepting a token.
//!
//! The input slice is the only bound on scanning and decoded string length.
//! Callers must bound it before parsing. Number length, range, nesting, value
//! counts, delimiters, and output escaping remain the caller's policy.
//!
//! ```
//! use fictionet::stdlib::codec::json_syntax::{read_string, scan_number};
//! let input = br#"["caf\u00e9",12.50]"#;
//! let (text, end) = read_string(input, 1)?;
//! assert_eq!(text, "café");
//! assert_eq!(end, 12);
//! let number_end = scan_number(input, end + 1)?;
//! assert_eq!(&input[end + 1..number_end], b"12.50");
//! # Ok::<(), fictionet::stdlib::codec::json_syntax::Error>(())
//! ```

extern crate alloc;

use alloc::string::String;

/// A lexical fault and its absolute byte offset into the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The token is incomplete at this offset.
    UnexpectedEnd(usize),
    /// A string's opening quote was expected at `offset`.
    UnexpectedByte {
        /// The byte found instead.
        byte: u8,
        /// Its offset into the input.
        offset: usize,
    },
    /// Invalid UTF-8 starts at this offset.
    InvalidUtf8(usize),
    /// The number grammar is broken at this offset.
    BadNumber(usize),
    /// An unknown escape or a non-hex digit occurs at this offset.
    BadEscape(usize),
    /// An unpaired surrogate's first backslash is at this offset.
    LoneSurrogate(usize),
    /// An unescaped byte below 0x20 occurs at this offset.
    ControlCharacter(usize),
}

impl Error {
    /// The fault's byte offset. An incomplete token reports the input's end.
    /// A start at or beyond the input's end reports that requested start.
    pub fn offset(&self) -> usize {
        match *self {
            Self::UnexpectedEnd(offset)
            | Self::UnexpectedByte { offset, .. }
            | Self::InvalidUtf8(offset)
            | Self::BadNumber(offset)
            | Self::BadEscape(offset)
            | Self::LoneSurrogate(offset)
            | Self::ControlCharacter(offset) => offset,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEnd(_) => f.write_str("the token ended early")?,
            Self::UnexpectedByte { byte, .. } => write!(f, "unexpected byte 0x{byte:02x}")?,
            Self::InvalidUtf8(_) => f.write_str("a string that is not UTF-8")?,
            Self::BadNumber(_) => f.write_str("a number that breaks the grammar")?,
            Self::BadEscape(_) => f.write_str("an unknown escape or non-hex digit")?,
            Self::LoneSurrogate(_) => f.write_str("half of a surrogate pair")?,
            Self::ControlCharacter(_) => {
                f.write_str("an unescaped control character in a string")?
            }
        }
        write!(f, " at byte {}", self.offset())
    }
}

impl core::error::Error for Error {}

/// Decodes a string starting at its opening quote, returning its text and
/// the absolute offset just after its closing quote. Trailing bytes are ignored.
/// A start at or beyond the slice's end returns [`Error::UnexpectedEnd`].
///
/// Escapes and surrogate pairs follow RFC 8259. Raw runs are checked for UTF-8
/// when a quote or backslash ends them. An unescaped control byte or the end
/// of input therefore takes precedence over invalid UTF-8 in an unfinished run.
/// The decoded text is no longer in bytes than the token between its quotes.
/// There is no separate size cap; bound the input slice before calling.
pub fn read_string(b: &[u8], start: usize) -> Result<(String, usize), Error> {
    match b.get(start) {
        Some(b'"') => {}
        Some(&byte) => {
            return Err(Error::UnexpectedByte {
                byte,
                offset: start,
            });
        }
        None => return Err(Error::UnexpectedEnd(start)),
    }
    let mut parser = StringParser { b, i: start };
    let text = parser.string()?;
    Ok((text, parser.i))
}

/// Where the number starting at `b[start]` ends, by the RFC 8259 grammar:
/// `-? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)?`.
///
/// Returns the absolute offset just after the number. It checks no delimiter:
/// `1x` ends at 1, but `01` fails at 1. No whitespace is skipped. An incomplete
/// number returns [`Error::UnexpectedEnd`]. A start at or beyond the slice's
/// end reports that start. This allocates nothing and imposes no length or
/// numeric range limit. The supplied slice bounds the scan.
pub fn scan_number(b: &[u8], start: usize) -> Result<usize, Error> {
    let mut i = start;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        None => return Err(Error::UnexpectedEnd(i)),
        Some(b'0') => {
            i += 1;
            if b.get(i).is_some_and(u8::is_ascii_digit) {
                return Err(Error::BadNumber(i));
            }
        }
        Some(b'1'..=b'9') => i = digits(b, i + 1),
        Some(_) => return Err(Error::BadNumber(i)),
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
        None => Err(Error::UnexpectedEnd(i)),
        Some(c) if c.is_ascii_digit() => Ok(digits(b, i + 1)),
        Some(_) => Err(Error::BadNumber(i)),
    }
}

struct StringParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl StringParser<'_> {
    /// A string, starting at its opening quote.
    fn string(&mut self) -> Result<String, Error> {
        self.i += 1;
        let mut out = String::new();
        let mut run = self.i;
        loop {
            match self.b.get(self.i) {
                None => return Err(Error::UnexpectedEnd(self.i)),
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
                Some(&c) if c < 0x20 => return Err(Error::ControlCharacter(self.i)),
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
            Err(e) => Err(Error::InvalidUtf8(run + e.valid_up_to())),
        }
    }

    /// One escape, starting at its backslash. It leaves `i` after it.
    fn escape(&mut self) -> Result<char, Error> {
        let start = self.i;
        self.i += 1;
        let c = match self.b.get(self.i) {
            None => return Err(Error::UnexpectedEnd(self.i)),
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
                    0xdc00..=0xdfff => Err(Error::LoneSurrogate(start)),
                    _ => char::from_u32(high).ok_or(Error::LoneSurrogate(start)),
                };
            }
            Some(_) => return Err(Error::BadEscape(self.i)),
        };
        self.i += 1;
        Ok(c)
    }

    /// The `\uXXXX` that must follow a high surrogate, and the character
    /// the pair makes.
    fn low_surrogate(&mut self, high: u32, start: usize) -> Result<char, Error> {
        for want in *b"\\u" {
            match self.b.get(self.i) {
                None => return Err(Error::UnexpectedEnd(self.i)),
                Some(&c) if c == want => self.i += 1,
                Some(_) => return Err(Error::LoneSurrogate(start)),
            }
        }
        let low = self.hex4()?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(Error::LoneSurrogate(start));
        }
        let c = 0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00);
        char::from_u32(c).ok_or(Error::LoneSurrogate(start))
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let mut n = 0u32;
        for _ in 0..4 {
            let d = match self.b.get(self.i) {
                None => return Err(Error::UnexpectedEnd(self.i)),
                Some(&c) => match (c as char).to_digit(16) {
                    Some(d) => d,
                    None => return Err(Error::BadEscape(self.i)),
                },
            };
            n = n * 16 + d;
            self.i += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString, vec};

    type FaultCase = (&'static [u8], fn(usize) -> Error, usize);

    #[test]
    fn strings_decode_escapes_and_unicode_boundaries() {
        for (token, text) in [
            (r#""""#, ""),
            (
                r#""a\"b\\c\/d\be\ff\ng\rh\ti""#,
                "a\"b\\c/d\u{8}e\u{c}f\ng\rh\ti",
            ),
            (
                r#""\u0000\u001f\u007f\u0080\u07ff\u0800""#,
                "\0\u{1f}\u{7f}\u{80}\u{7ff}\u{800}",
            ),
            (r#""\ud7ff\uE000\uffff""#, "\u{d7ff}\u{e000}\u{ffff}"),
            (r#""\ud800\udc00\uDBFF\uDFFF""#, "\u{10000}\u{10ffff}"),
            (r#""Café 日本 😀""#, "Café 日本 😀"),
        ] {
            for prefix in [b"".as_slice(), b"\xff\0 "] {
                let mut input = prefix.to_vec();
                input.extend_from_slice(token.as_bytes());
                input.extend_from_slice(b"\xff trailing");
                assert_eq!(
                    read_string(&input, prefix.len()),
                    Ok((text.to_string(), prefix.len() + token.len())),
                    "{input:?}"
                );
            }
        }
    }

    #[test]
    fn strings_report_exact_fault_offsets() {
        let cases: &[FaultCase] = &[
            (b"", Error::UnexpectedEnd, 0),
            (b"\"", Error::UnexpectedEnd, 1),
            (b"\"\\", Error::UnexpectedEnd, 2),
            (br#""\x""#, Error::BadEscape, 2),
            (br#""\u12g4""#, Error::BadEscape, 5),
            (br#""\ud800""#, Error::LoneSurrogate, 1),
            (br#""\udbff""#, Error::LoneSurrogate, 1),
            (br#""ab\udc00""#, Error::LoneSurrogate, 3),
            (br#""\udfff""#, Error::LoneSurrogate, 1),
            (br#""\ud800\n""#, Error::LoneSurrogate, 1),
            (br#""\ud800\udbff""#, Error::LoneSurrogate, 1),
            (br#""\ud800\ue000""#, Error::LoneSurrogate, 1),
            (br#""\ud800\u12g4""#, Error::BadEscape, 11),
            (b"\"a\tb\"", Error::ControlCharacter, 2),
            (b"\"a\xffb\"", Error::InvalidUtf8, 2),
            (b"\"\x80\"", Error::InvalidUtf8, 1),
            (b"\"\xc0\x80\"", Error::InvalidUtf8, 1),
            (b"\"\xed\xa0\x80\"", Error::InvalidUtf8, 1),
            (b"\"\xf4\x90\x80\x80\"", Error::InvalidUtf8, 1),
            (b"\"ab\xc3\"", Error::InvalidUtf8, 3),
            (b"\"\xff\\x\"", Error::InvalidUtf8, 1),
            (b"\"\xff\n", Error::ControlCharacter, 2),
            (b"\"\xff", Error::UnexpectedEnd, 2),
        ];
        for &(token, error, offset) in cases {
            for start in [0, 3] {
                let mut input = vec![b' '; start];
                input.extend_from_slice(token);
                let expected = error(start + offset);
                assert_eq!(read_string(&input, start), Err(expected), "{input:?}");
                assert_eq!(expected.offset(), start + offset);
            }
        }
        for byte in 0..0x20 {
            assert_eq!(
                read_string(&[b'"', byte, b'"'], 0),
                Err(Error::ControlCharacter(1))
            );
        }
    }

    #[test]
    fn incomplete_strings_report_the_end_at_every_cut() {
        for token in [br#""\u0041""#.as_slice(), br#""\ud800\udc00""#] {
            for end in 0..token.len() {
                assert_eq!(
                    read_string(&token[..end], 0),
                    Err(Error::UnexpectedEnd(end))
                );
            }
        }
    }

    #[test]
    fn numbers_stop_after_the_grammar_without_conversion() {
        for token in ["0", "-0", "123", "-1.25", "1e400", "1E+2", "2.5e-03"] {
            for suffix in ["", ",", "]", " ", "x", ".5"] {
                let input = format!("prefix{token}{suffix}");
                // A dot after an integer begins its fraction.
                let end = if suffix == ".5" && !token.contains(['.', 'e', 'E']) {
                    input.len()
                } else {
                    6 + token.len()
                };
                assert_eq!(scan_number(input.as_bytes(), 6), Ok(end), "{input}");
            }
        }
        let long = "1".repeat(2048);
        assert_eq!(scan_number(long.as_bytes(), 0), Ok(long.len()));
        let string = format!("\"{long}\"");
        assert_eq!(read_string(string.as_bytes(), 0), Ok((long, string.len())));
    }

    #[test]
    fn numbers_report_exact_fault_offsets() {
        let cases: &[FaultCase] = &[
            (b"", Error::UnexpectedEnd, 0),
            (b"-", Error::UnexpectedEnd, 1),
            (b"00", Error::BadNumber, 1),
            (b"-01", Error::BadNumber, 2),
            (b"+1", Error::BadNumber, 0),
            (b" 1", Error::BadNumber, 0),
            (b".5", Error::BadNumber, 0),
            (b"-x", Error::BadNumber, 1),
            (b"1.", Error::UnexpectedEnd, 2),
            (b"1.x", Error::BadNumber, 2),
            (b"1e", Error::UnexpectedEnd, 2),
            (b"1e+", Error::UnexpectedEnd, 3),
            (b"1E-", Error::UnexpectedEnd, 3),
            (b"1e+x", Error::BadNumber, 3),
            (b"1e-\xff", Error::BadNumber, 3),
            (b"NaN", Error::BadNumber, 0),
            (b"Infinity", Error::BadNumber, 0),
        ];
        for &(token, error, offset) in cases {
            for start in [0, 3] {
                let mut input = vec![b' '; start];
                input.extend_from_slice(token);
                assert_eq!(
                    scan_number(&input, start),
                    Err(error(start + offset)),
                    "{input:?}"
                );
            }
        }
    }

    #[test]
    fn start_offsets_are_checked_without_skipping_whitespace() {
        for start in [1, 2, usize::MAX] {
            assert_eq!(read_string(b"0", start), Err(Error::UnexpectedEnd(start)));
            assert_eq!(scan_number(b"0", start), Err(Error::UnexpectedEnd(start)));
        }
        assert_eq!(
            read_string(b" \"x\"", 0),
            Err(Error::UnexpectedByte {
                byte: b' ',
                offset: 0
            })
        );
        assert_eq!(
            Error::BadEscape(5).to_string(),
            "an unknown escape or non-hex digit at byte 5"
        );
    }
}
