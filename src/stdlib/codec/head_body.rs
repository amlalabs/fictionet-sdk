//! Header collection and borrowed head and Content-Length body framing.
//! Protocol modules own start lines, header names, length rules, and errors.
//! [`append_header_line`] unfolds separated lines. [`set_header`] and
//! [`remove_header`] edit fields using the caller's name matching policy.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use fictionet::stdlib::codec::ascii::{
    is_tchar as is_token_byte, trim_ows as trim_frame_ws, trim_ows_str as trim_ws,
};
use fictionet::stdlib::codec::{Buffer, LineError};

/// One header field: its name as it came and its value with folded lines
/// joined by single spaces and the ends trimmed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// The field name.
    pub name: String,
    /// The field value.
    pub value: String,
}

impl Header {
    /// A header with this name and value.
    #[inline]
    pub fn new(name: &str, value: &str) -> Header {
        Header {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

/// Appends one complete header line without its ending, or unfolds a
/// continuation into the last field. No input cursor is moved or retained.
/// The caller checks line endings and byte limits before this call, then
/// validates completed field values after collecting all lines.
///
/// A line starting with a space or tab continues the last field. Its ends
/// are trimmed of spaces and tabs. Empty continuations add nothing; two
/// nonempty pieces are joined with one space. An orphan continuation returns
/// `malformed`, even if it is empty or `max_headers` is zero.
///
/// Other lines add a field. Before checking syntax, a count at or above
/// `max_headers` returns `too_many`. This limit is used without clamping and
/// does not count continuations. A missing colon or a name rejected by
/// `valid_name` returns `malformed`. The predicate sees the name before the
/// first colon, with trailing spaces and tabs removed. Value ends are also
/// trimmed of spaces and tabs. Errors leave `headers` unchanged.
///
/// ```
/// use fictionet::stdlib::codec::head_body::{Header, append_header_line};
/// let mut headers = Vec::new();
/// for line in ["X-Note \t: ", "\tfirst", " \t", " second: part "] {
///     append_header_line(&mut headers, line, 1, |name| name == "X-Note",
///         "header", "count")?;
/// }
/// assert_eq!(headers, [Header::new("X-Note", "first second: part")]);
/// assert_eq!(append_header_line(&mut headers, "bad", 1, |_| true,
///     "header", "count"), Err("count"));
/// # Ok::<(), &str>(())
/// ```
pub fn append_header_line<E>(
    headers: &mut Vec<Header>,
    line: &str,
    max_headers: usize,
    valid_name: impl FnOnce(&str) -> bool,
    malformed: E,
    too_many: E,
) -> Result<(), E> {
    if line.starts_with([' ', '\t']) {
        let last = headers.last_mut().ok_or(malformed)?;
        let more = trim_ws(line);
        if !more.is_empty() {
            if !last.value.is_empty() {
                last.value.push(' ');
            }
            last.value.push_str(more);
        }
        return Ok(());
    }
    if headers.len() >= max_headers {
        return Err(too_many);
    }
    let Some(colon) = line.find(':') else {
        return Err(malformed);
    };
    let name = line[..colon].trim_end_matches([' ', '\t']);
    if !valid_name(name) {
        return Err(malformed);
    }
    headers.push(Header::new(name, trim_ws(&line[colon + 1..])));
    Ok(())
}

/// Replaces the first matching field's value and removes later matches.
/// Keeps the first field's name spelling and position, and the order of
/// other fields. With no match, appends a field using `name` and `value`.
/// `same_name` compares a stored name to `name`, including any caller aliases.
/// No text is trimmed or validated, and no count or byte limits are enforced.
/// The caller validates the completed message before writing it.
///
/// ```
/// use fictionet::stdlib::codec::head_body::{Header, set_header};
/// let mut headers = vec![Header::new("x", "old"), Header::new("X", "duplicate")];
/// set_header(&mut headers, "X", "new", str::eq_ignore_ascii_case);
/// set_header(&mut headers, "Y", "last", str::eq_ignore_ascii_case);
/// assert_eq!(headers, [Header::new("x", "new"), Header::new("Y", "last")]);
/// ```
pub fn set_header(
    headers: &mut Vec<Header>,
    name: &str,
    value: &str,
    same_name: impl Fn(&str, &str) -> bool,
) {
    match headers.iter().position(|h| same_name(&h.name, name)) {
        Some(i) => {
            headers[i].value = value.to_string();
            let mut seen = 0usize;
            headers.retain(|h| {
                if !same_name(&h.name, name) {
                    return true;
                }
                seen += 1;
                seen == 1
            });
        }
        None => headers.push(Header::new(name, value)),
    }
}

/// Removes every matching field and returns the count removed. Other fields
/// keep their order. `same_name` compares a stored name to `name`, including
/// any caller aliases. No names or values are trimmed or validated.
///
/// ```
/// use fictionet::stdlib::codec::head_body::{Header, remove_header};
/// let mut headers = vec![Header::new("x", "one"), Header::new("X", "two")];
/// assert_eq!(remove_header(&mut headers, "X", str::eq_ignore_ascii_case), 2);
/// assert!(headers.is_empty());
/// ```
pub fn remove_header(
    headers: &mut Vec<Header>,
    name: &str,
    same_name: impl Fn(&str, &str) -> bool,
) -> usize {
    let before = headers.len();
    headers.retain(|h| !same_name(&h.name, name));
    before - headers.len()
}

/// Incrementally finds a head and its declared body without copying input.
/// Keep the whole unconsumed unit in `input` across calls. Only offsets are
/// retained. Partial input, including a missing body at EOF, returns `None`;
/// the enclosing decoder leaves truncation reporting to `Stream`.
#[derive(Debug)]
pub struct Scanner {
    max_line: usize,
    max_head: usize,
    crlf: bool,
    scanned: usize,
    line_scan: usize,
    body: Option<(usize, usize)>,
}

impl Scanner {
    /// Sets the line content and total head limits. `crlf` requires CRLF;
    /// otherwise LF is also accepted. A head needs a start line and a blank
    /// line. Length validation belongs to the callback passed to `scan`.
    #[inline]
    pub fn new(max_line: usize, max_head: usize, crlf: bool) -> Self {
        Self {
            max_line: max_line.min(Buffer::MAX_LIMIT.saturating_sub(2)),
            max_head,
            crlf,
            scanned: 0,
            line_scan: 0,
            body: None,
        }
    }

    /// Whether no complete head line or body boundary has been retained.
    #[inline]
    pub fn is_start(&self) -> bool {
        self.scanned == 0 && self.body.is_none()
    }

    /// Finds the head end. No partial line is consumed, including at EOF.
    /// Line or head limits return `TooLong`; invalid endings return `BareLf`.
    #[inline]
    pub fn scan_head(&mut self, input: &[u8]) -> Result<Option<usize>, LineError> {
        loop {
            let room = self.max_head.saturating_sub(self.scanned);
            let rest = input.get(self.scanned..).unwrap_or_default();
            let stop = rest.len().min(room).min(self.max_line.saturating_add(2));
            let window = &rest[..stop];
            let from = self.line_scan.min(stop);
            if let Some(i) = window[from..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|i| i + from)
            {
                let cr = i > 0 && window[i - 1] == b'\r';
                let content = i - usize::from(cr);
                if content > self.max_line {
                    return Err(LineError::TooLong { max: self.max_line });
                }
                if self.crlf && !cr {
                    return Err(LineError::BareLf);
                }
                self.scanned += i + 1;
                self.line_scan = 0;
                if content == 0 && (!self.crlf || self.scanned > 2) {
                    return Ok(Some(self.scanned));
                }
            } else {
                self.line_scan = stop;
                if stop >= room || stop >= self.max_line.saturating_add(2) {
                    return Err(LineError::TooLong {
                        max: self.max_head.min(self.max_line),
                    });
                }
                return Ok(None);
            }
        }
    }

    /// Returns `(head_end, unit_end)` when the body is complete, then resets.
    /// `length` examines the borrowed head once. `line_error` must map every
    /// line error to a protocol error, including unexpected line errors.
    #[inline]
    pub fn scan<E>(
        &mut self,
        input: &[u8],
        length: impl FnOnce(&[u8]) -> Result<usize, E>,
        line_error: impl Fn(LineError) -> E,
    ) -> Result<Option<(usize, usize)>, E> {
        if self.body.is_none() {
            let Some(head) = self.scan_head(input).map_err(&line_error)? else {
                return Ok(None);
            };
            self.body = Some((head, length(&input[..head])?));
        }
        let (head, length) = self.body.unwrap();
        let used = head
            .checked_add(length)
            .ok_or_else(|| line_error(LineError::TooLong { max: self.max_head }))?;
        if input.len() < used {
            return Ok(None);
        }
        self.scanned = 0;
        self.line_scan = 0;
        self.body = None;
        Ok(Some((head, used)))
    }
}

/// Reads framing lengths independently of unrelated head syntax.
/// `lines` excludes the start line and line endings. The name predicate
/// handles protocol aliases. `parse` validates decimal syntax and limits.
/// Equal duplicates are accepted only when `allow_equal` is true. Folding
/// that inserts a space inside a length and conflicting duplicates fail.
#[inline]
pub fn content_length<'a, E: Clone>(
    lines: impl Iterator<Item = &'a [u8]>,
    is_length: impl Fn(&[u8]) -> bool,
    parse: impl Fn(&str) -> Result<usize, E>,
    allow_equal: bool,
    malformed: E,
) -> Result<Option<usize>, E> {
    let mut length = None;
    let mut active = false;
    let mut value: Option<&[u8]> = None;
    for line in lines {
        let trimmed = trim_frame_ws(line);
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            if active && !trimmed.is_empty() {
                // Unfolding two nonempty pieces inserts a space. A decimal
                // Content-Length cannot contain that space.
                if value.is_some() {
                    return Err(malformed.clone());
                }
                value = Some(trimmed);
            }
            continue;
        }
        if active {
            store_length(
                &mut length,
                value.unwrap_or_default(),
                &parse,
                allow_equal,
                &malformed,
            )?;
        }
        value = None;
        let colon = line.iter().position(|&b| b == b':');
        let name = colon.and_then(|n| line.get(..n)).unwrap_or(line);
        let name = trim_frame_ws(name);
        active = is_length(name);
        if !active {
            // A recognizable length name with a missing colon or an invalid
            // suffix must not be mistaken for an unrelated bad header.
            let token = name
                .split(|b| !is_token_byte(*b))
                .next()
                .unwrap_or_default();
            if is_length(token) {
                return Err(malformed.clone());
            }
        }
        if active {
            let at = colon
                .ok_or(malformed.clone())?
                .checked_add(1)
                .ok_or(malformed.clone())?;
            let bytes = line.get(at..).ok_or(malformed.clone())?;
            let bytes = trim_frame_ws(bytes);
            if !bytes.is_empty() {
                value = Some(bytes);
            }
        }
    }
    if active {
        store_length(
            &mut length,
            value.unwrap_or_default(),
            &parse,
            allow_equal,
            &malformed,
        )?;
    }
    Ok(length)
}

#[inline]
fn store_length<E: Clone>(
    length: &mut Option<usize>,
    bytes: &[u8],
    parse: &impl Fn(&str) -> Result<usize, E>,
    allow_equal: bool,
    malformed: &E,
) -> Result<(), E> {
    let value = core::str::from_utf8(bytes).map_err(|_| malformed.clone())?;
    let n = parse(value)?;
    if length.is_some_and(|old| !allow_equal || old != n) {
        return Err(malformed.clone());
    }
    *length = Some(n);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Decode, Fail, Step, Stream};
    use super::*;
    use alloc::{vec, vec::Vec};

    #[test]
    fn header_lines_preserve_fields_and_only_trim_spaces_and_tabs() {
        let mut headers = Vec::new();
        for line in ["X \t: \t", " \t", "\tfirst\t", " ", " second: part "] {
            append_header_line(&mut headers, line, 1, |name| name == "X", "line", "count").unwrap();
        }
        assert_eq!(headers, [Header::new("X", "first second: part")]);
        append_header_line(
            &mut headers,
            "X: \t\u{a0}value\u{a0}\t",
            usize::MAX,
            |name| name == "X",
            "line",
            "count",
        )
        .unwrap();
        assert_eq!(
            headers,
            [
                Header::new("X", "first second: part"),
                Header::new("X", "\u{a0}value\u{a0}"),
            ]
        );
    }

    #[test]
    fn header_line_errors_leave_the_collection_unchanged() {
        let original = vec![Header::new("Existing", "value")];
        let mut headers = original.clone();
        for line in ["", "No colon", ": empty", "Bad Name: value", "Y: value"] {
            assert_eq!(
                append_header_line(
                    &mut headers,
                    line,
                    2,
                    |name| name == "X",
                    String::from("line"),
                    String::from("count")
                ),
                Err(String::from("line")),
            );
            assert_eq!(headers, original);
        }
        for max in [0, 1] {
            for line in ["X: valid", "Bad Name: value", "No colon"] {
                assert_eq!(
                    append_header_line(
                        &mut headers,
                        line,
                        max,
                        |name| name == "X",
                        "line",
                        "count"
                    ),
                    Err("count"),
                );
                assert_eq!(headers, original);
            }
            for line in [" \t", "\tmore"] {
                let mut empty = Vec::new();
                assert_eq!(
                    append_header_line(&mut empty, line, max, |_| true, "line", "count"),
                    Err("line"),
                );
                assert!(empty.is_empty());
            }
        }
    }

    #[test]
    fn header_edits_use_the_supplied_matching_policy() {
        let mut headers = vec![
            Header::new("A", "first"),
            Header::new("a", "lowercase"),
            Header::new("B", "middle"),
            Header::new("A", "duplicate"),
        ];
        set_header(&mut headers, "A", " \tnew\t ", |a, b| a == b);
        assert_eq!(
            headers,
            [
                Header::new("A", " \tnew\t "),
                Header::new("a", "lowercase"),
                Header::new("B", "middle"),
            ]
        );
        assert_eq!(remove_header(&mut headers, "a", |a, b| a == b), 1);
        assert_eq!(remove_header(&mut headers, "missing", |a, b| a == b), 0);
        set_header(&mut headers, "C", "last", |a, b| a == b);
        assert_eq!(
            headers,
            [
                Header::new("A", " \tnew\t "),
                Header::new("B", "middle"),
                Header::new("C", "last"),
            ]
        );
    }

    struct Units(Scanner);

    fn length(head: &[u8]) -> Result<usize, &'static str> {
        let lines = head
            .split(|&b| b == b'\n')
            .skip(1)
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
        content_length(
            lines,
            |name| name.eq_ignore_ascii_case(b"Content-Length"),
            |value| {
                let n = value.parse::<usize>().map_err(|_| "length")?;
                if n > 4 {
                    return Err("limit");
                }
                Ok(n)
            },
            true,
            "length",
        )
        .map(|n| n.unwrap_or(0))
    }

    impl Decode for Units {
        type Item = (Vec<u8>, Vec<u8>);
        type Error = LineError;
        const NAME: &'static str = "head-body test";
        fn capacity(&self) -> usize {
            132
        }
        fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Self::Item>, Self::Error> {
            Ok(
                match self.0.scan(
                    input,
                    |head| length(head).map_err(|_| LineError::Unterminated),
                    |error| error,
                )? {
                    Some((head, used)) => {
                        Step::Item((input[..head].to_vec(), input[head..used].to_vec()), used)
                    }
                    None => Step::Need,
                },
            )
        }
    }

    #[test]
    fn every_split_and_bytewise_input() {
        for crlf in [false, true] {
            let bytes = b"START\r\nContent-Length: 4\r\n\r\nbodyNEXT\r\n\r\n";
            let expected = vec![
                (
                    b"START\r\nContent-Length: 4\r\n\r\n".to_vec(),
                    b"body".to_vec(),
                ),
                (b"NEXT\r\n\r\n".to_vec(), vec![]),
            ];
            for split in 0..=bytes.len() {
                let mut stream = Stream::new(Units(Scanner::new(64, 128, crlf)));
                let mut items = Vec::new();
                for chunk in [&bytes[..split], &bytes[split..]] {
                    assert_eq!(stream.push(chunk), chunk.len());
                    while let Some(item) = stream.next() {
                        items.push(item.unwrap());
                    }
                }
                stream.end();
                assert_eq!(stream.next(), None);
                assert_eq!(items, expected, "split {split}");
            }
            let mut stream = Stream::new(Units(Scanner::new(64, 128, crlf)));
            let mut items = Vec::new();
            for byte in bytes {
                assert_eq!(stream.push(&[*byte]), 1);
                while let Some(item) = stream.next() {
                    items.push(item.unwrap());
                }
            }
            assert_eq!(items, expected);
        }
    }

    #[test]
    fn content_length_limit_and_missing_body_at_eof() {
        let mut scanner = Scanner::new(64, 128, true);
        let bytes = b"START\r\nContent-Length: 4\r\n\r\nbody";
        assert_eq!(scanner.scan(bytes, length, |_| "line"), Ok(Some((28, 32))));
        assert_eq!(
            scanner.scan(b"START\r\nContent-Length: 5\r\n\r\n", length, |_| "line"),
            Err("limit")
        );
        for body in [b"".as_slice(), b"bod"] {
            let mut stream = Stream::new(Units(Scanner::new(64, 128, true)));
            let mut bytes = b"START\r\nContent-Length: 4\r\n\r\n".to_vec();
            bytes.extend_from_slice(body);
            assert_eq!(stream.push(&bytes), bytes.len());
            assert_eq!(stream.next(), None);
            stream.end();
            assert_eq!(
                stream.next(),
                Some(Err(Fail::Truncated {
                    unread: bytes.len()
                }))
            );
        }
    }

    #[test]
    fn malformed_lines_are_errors() {
        let mut scanner = Scanner::new(64, 128, true);
        assert_eq!(
            scanner.scan(b"START\n\n", length, |_| "malformed head"),
            Err("malformed head")
        );
    }
}
