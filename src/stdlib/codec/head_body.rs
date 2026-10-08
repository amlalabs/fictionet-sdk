//! Borrowed head and Content-Length body framing for SIP and RTSP.
//! Protocol modules own start lines, header names, length rules, and errors.

extern crate alloc;

use alloc::string::{String, ToString};
use fictionet::stdlib::codec::ascii::{is_tchar as is_token_byte, trim_ows as trim_frame_ws};
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
