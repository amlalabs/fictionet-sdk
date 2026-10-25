//! The string values in JSON and in a page's scripts: where each one's
//! characters sit in the source, and the names of the keys it sits under,
//! so an edit can rewrite a value and leave the data valid.

use std::ops::Range;

/// How the source is written.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Code {
    /// JSON: double quotes only, no comments.
    Json,
    /// A script: single and double quotes, template strings and comments.
    Script,
}

/// A string value: its characters with the source bytes behind each, the
/// quote it is written in, and the keys it sits under.
pub(super) struct Literal {
    /// The bytes between the quotes.
    pub content: Range<usize>,
    pub quote: u8,
    /// Each character of the value with the source bytes it is written in.
    pub characters: Vec<(char, Range<usize>)>,
    /// The key the value belongs to, after the key that holds it, as
    /// `parent.key`; empty when it has none.
    pub label: String,
}

/// The string values (not keys) in `range` of `source`.
pub(super) fn values(source: &str, range: Range<usize>, code: Code) -> Vec<Literal> {
    let bytes = source.as_bytes();
    let end = range.end.min(source.len());
    let mut at = range.start;
    let mut found = Vec::new();
    // The key each open object or array belongs to.
    let mut holders: Vec<String> = Vec::new();
    let mut key: Option<String> = None;
    while at < end {
        let byte = bytes[at];
        match byte {
            b'/' if code == Code::Script && bytes.get(at + 1) == Some(&b'/') => {
                at = source[at..end].find('\n').map_or(end, |offset| at + offset);
                continue;
            }
            b'/' if code == Code::Script && bytes.get(at + 1) == Some(&b'*') => {
                at = source[at + 2..end]
                    .find("*/")
                    .map_or(end, |offset| at + 2 + offset + 2);
                continue;
            }
            b'{' | b'[' | b'(' => {
                let holder = key
                    .take()
                    .or_else(|| holders.last().cloned())
                    .unwrap_or_default();
                holders.push(holder);
            }
            b'}' | b']' | b')' => {
                holders.pop();
                key = None;
            }
            b',' | b';' => key = None,
            b'"' => {}
            b'\'' | b'`' if code == Code::Script => {}
            _ if code == Code::Script
                && (byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$') =>
            {
                // An identifier, which names a key when a colon follows.
                let start = at;
                while at < end
                    && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'_' | b'$'))
                {
                    at += 1;
                }
                if names_key(bytes, at, end) {
                    key = Some(source[start..at].to_owned());
                }
                continue;
            }
            _ => {
                at += 1;
                continue;
            }
        }
        if !matches!(byte, b'"' | b'\'' | b'`') {
            at += 1;
            continue;
        }
        let Some(close) = closing(bytes, at, end, byte) else {
            // Not a string after all (a regular expression, say): read on
            // after its quote.
            at += 1;
            continue;
        };
        let content = at + 1..close;
        at = close + 1;
        if byte == b'`' && source[content.clone()].contains("${") {
            continue;
        }
        let characters = decode(source, content.clone());
        if names_key(bytes, at, end) {
            key = Some(characters.iter().map(|(character, _)| *character).collect());
            continue;
        }
        let parent = holders.last().filter(|holder| !holder.is_empty());
        let label = match (parent, &key) {
            (Some(parent), Some(key)) => format!("{parent}.{key}"),
            (None, Some(key)) => key.clone(),
            (Some(parent), None) => parent.clone(),
            (None, None) => String::new(),
        };
        key = None;
        found.push(Literal {
            content,
            quote: byte,
            characters,
            label,
        });
    }
    found
}

/// Whether a colon (and not `::`) follows `at`, past any spaces.
fn names_key(bytes: &[u8], mut at: usize, end: usize) -> bool {
    while at < end && bytes[at].is_ascii_whitespace() {
        at += 1;
    }
    at < end && bytes[at] == b':' && bytes.get(at + 1) != Some(&b':')
}

/// Where the string opened by `quote` at `at` closes. A single- or
/// double-quoted string never runs over a line, so one that seems to is
/// not a string.
fn closing(bytes: &[u8], at: usize, end: usize, quote: u8) -> Option<usize> {
    let mut index = at + 1;
    while index < end {
        match bytes[index] {
            b'\\' => index += 2,
            b'\n' | b'\r' if quote != b'`' => return None,
            byte if byte == quote => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// The characters of the string whose content is `content`, escapes
/// decoded, each with the source bytes it is written in.
fn decode(source: &str, content: Range<usize>) -> Vec<(char, Range<usize>)> {
    let text = &source[content.clone()];
    let mut characters = Vec::new();
    let mut offset = 0;
    while offset < text.len() {
        let start = content.start + offset;
        let rest = &text[offset..];
        let Some(escaped) = rest.strip_prefix('\\') else {
            let character = rest.chars().next().expect("a character");
            characters.push((character, start..start + character.len_utf8()));
            offset += character.len_utf8();
            continue;
        };
        let (character, length) = escape(escaped);
        if let Some(character) = character {
            characters.push((character, start..start + 1 + length));
        }
        offset += 1 + length;
    }
    characters
}

/// The character an escape names (the text after its backslash), if it
/// names one, and the escape's length after the backslash.
fn escape(escaped: &str) -> (Option<char>, usize) {
    let hex = |digits: &str| u32::from_str_radix(digits, 16).ok();
    let Some(first) = escaped.chars().next() else {
        return (None, 0);
    };
    match first {
        'n' => (Some('\n'), 1),
        't' => (Some('\t'), 1),
        'r' => (Some('\r'), 1),
        'b' => (Some('\u{8}'), 1),
        'f' => (Some('\u{c}'), 1),
        'v' => (Some('\u{b}'), 1),
        '0' if !escaped[1..].starts_with(|c: char| c.is_ascii_digit()) => (Some('\0'), 1),
        // A backslash before a line break continues the string.
        '\n' => (None, 1),
        '\r' => (None, if escaped[1..].starts_with('\n') { 2 } else { 1 }),
        'x' if escaped.len() >= 3 => match escaped.get(1..3).and_then(hex) {
            Some(code) => (char::from_u32(code), 3),
            None => (Some('x'), 1),
        },
        'u' if escaped[1..].starts_with('{') => {
            let close = escaped.find('}');
            match close.and_then(|close| escaped.get(2..close)).and_then(hex) {
                Some(code) => (
                    char::from_u32(code).or(Some('\u{fffd}')),
                    close.unwrap() + 1,
                ),
                None => (Some('u'), 1),
            }
        }
        'u' => {
            let Some(high) = escaped.get(1..5).and_then(hex) else {
                return (Some('u'), 1);
            };
            // A surrogate pair is two escapes for one character.
            if (0xd800..0xdc00).contains(&high)
                && let Some(low) = escaped
                    .get(5..11)
                    .and_then(|pair| pair.strip_prefix("\\u"))
                    .and_then(hex)
                && (0xdc00..0xe000).contains(&low)
            {
                let code = 0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00);
                return (char::from_u32(code), 11);
            }
            (char::from_u32(high).or(Some('\u{fffd}')), 5)
        }
        other => (Some(other), other.len_utf8()),
    }
}

/// `text` written inside a string quoted with `quote`; in a page's script
/// a closing tag is broken up so the script stays whole.
pub(super) fn escaped(text: &str, quote: u8, in_page: bool) -> String {
    let mut written = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => written.push_str("\\\\"),
            '\n' => written.push_str("\\n"),
            '\r' => written.push_str("\\r"),
            '\t' => written.push_str("\\t"),
            '/' if in_page && written.ends_with('<') => written.push_str("\\/"),
            character if character as u32 == u32::from(quote) => {
                written.push('\\');
                written.push(character);
            }
            '`' | '$' if quote == b'`' => {
                written.push('\\');
                written.push(character);
            }
            character if (character as u32) < 0x20 => {
                written.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => written.push(character),
        }
    }
    written
}
