//! Head and body framing: `head_size` counts exactly what the start line
//! and `write_headers` emit under the given limits; `Scanner::scan_head`
//! never panics, ends a head only at a blank line within the limits, and
//! gives the same answer whether the input arrives whole or in two parts;
//! `content_length` never panics and finds no length where no length
//! header is.

extern crate alloc;

use super::bytes;
use alloc::{string::String, vec::Vec};
use fictionet::stdlib::codec::{
    LineError,
    head_body::{Header, Scanner, content_length, head_size, write_headers},
};

/// A symbolic ASCII string of at most `N` bytes.
fn ascii<const N: usize>() -> String {
    let (bytes, len) = bytes::<N>();
    let bytes = &bytes[..len];
    kani::assume(bytes.iter().all(|b| b.is_ascii()));
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[kani::proof]
#[kani::unwind(6)]
fn head_size_counts_exactly_what_is_written() {
    let start: usize = kani::any();
    kani::assume(start <= 3);
    let headers = [
        Header::new(&ascii::<2>(), &ascii::<2>()),
        Header::new(&ascii::<2>(), &ascii::<2>()),
    ];
    let count: usize = kani::any();
    kani::assume(count <= headers.len());
    let headers = &headers[..count];
    let max_line: usize = kani::any();
    let max_head: usize = kani::any();
    let mut out = Vec::new();
    out.resize(start, b'S');
    out.extend_from_slice(b"\r\n");
    write_headers(headers, &mut out);
    let longest_line = headers
        .iter()
        .map(|h| h.name.len() + 2 + h.value.len())
        .max()
        .unwrap_or(0)
        .max(start);
    match head_size(start, headers, max_line, max_head, ()) {
        Ok(size) => {
            assert_eq!(size, out.len());
            assert!(longest_line <= max_line);
            assert!(size <= max_head);
        }
        Err(()) => assert!(longest_line > max_line || out.len() > max_head),
    }
}

/// The lines of `head` without their endings, where `head` ends in a newline.
fn lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head.split_inclusive(|b| *b == b'\n').map(|line| {
        line.strip_suffix(b"\r\n")
            .or_else(|| line.strip_suffix(b"\n"))
            .unwrap()
    })
}

#[kani::proof]
#[kani::unwind(8)]
fn scanning_a_head_is_bounded_and_independent_of_chunking() {
    let (input, len) = bytes::<6>();
    let input = &input[..len];
    let max_line: usize = kani::any();
    kani::assume(max_line <= 4);
    let max_head: usize = kani::any();
    kani::assume(max_head <= 6);
    let crlf: bool = kani::any();

    let mut whole = Scanner::new(max_line, max_head, crlf);
    let result = whole.scan_head(input);
    match result {
        Ok(Some(head)) => {
            assert!(head >= 1 && head <= len);
            assert!(head <= max_head);
            let bytes = &input[..head];
            assert!(bytes.ends_with(b"\n"));
            let last = lines(bytes).last().unwrap();
            assert!(last.is_empty());
            for line in lines(bytes) {
                assert!(line.len() <= max_line);
            }
            if crlf {
                assert!(bytes.ends_with(b"\r\n"));
                assert!(
                    bytes
                        .split_inclusive(|b| *b == b'\n')
                        .all(|line| line.ends_with(b"\r\n"))
                );
            }
            assert!(!whole.is_start());
        }
        Ok(None) => {
            // No blank line yet, and no line has already passed its limit.
            assert!(len < max_head);
            // With CRLF required, one leading CRLF is passed over.
            assert!(input.iter().position(|b| *b == b'\n').is_none_or(|first| {
                let line = &input[..=first];
                let content = line
                    .strip_suffix(b"\r\n")
                    .or_else(|| line.strip_suffix(b"\n"));
                content
                    .is_some_and(|c| c.len() <= max_line && (!c.is_empty() || (crlf && first == 1)))
            }));
        }
        Err(LineError::TooLong { .. }) => {}
        Err(LineError::BareLf) => {
            assert!(crlf);
            let first = input.iter().position(|b| *b == b'\n').unwrap();
            assert!(first == 0 || input[first - 1] != b'\r');
        }
        Err(LineError::Unterminated) => unreachable!(),
    }

    let split: usize = kani::any();
    kani::assume(split <= len);
    let mut parts = Scanner::new(max_line, max_head, crlf);
    let first = parts.scan_head(&input[..split]);
    match first {
        Ok(None) => assert_eq!(parts.scan_head(input), result),
        other => assert_eq!(other, result),
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn content_length_finds_no_length_without_a_length_header() {
    let (a, alen) = bytes::<4>();
    let (b, blen) = bytes::<4>();
    let lines = [&a[..alen], &b[..blen]];
    let is_length = |name: &[u8]| name == b"L";
    let result = content_length(
        lines.iter().copied(),
        is_length,
        |value| value.parse::<usize>().map_err(|_| ()),
        kani::any(),
        (),
    );
    let names_a_length = lines.iter().any(|line| {
        let name = match line.iter().position(|b| *b == b':') {
            Some(colon) => &line[..colon],
            None => line,
        };
        name.trim_ascii().starts_with(b"L")
    });
    if !names_a_length {
        assert_eq!(result, Ok(None));
    }
    if let Ok(Some(n)) = result {
        // The value came from a line's digits.
        assert!(lines.iter().any(|line| {
            core::str::from_utf8(line).is_ok_and(|text| {
                text.trim_ascii().trim_start_matches("L:").trim().parse() == Ok(n)
            })
        }));
    }
}
