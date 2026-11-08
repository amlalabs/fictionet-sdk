//! Production head framing, supplementing the per-step body proofs.
//! Source: protocols/http1.rs fields:1667, request_framing:1735,
//! response_framing:1748, header_line:1787, request_head:1968.
//! native.rs:202 constructs RequestEvents with strict chunk framing.
use super::*;

fn find_byte(x: u8, text: &[u8]) -> Option<usize> {
    text.iter().position(|b| *b == x)
}

fn header(name: &str, value: &[u8]) -> Header {
    Header {
        name: name.into(),
        value: value.to_vec(),
    }
}

fn whitespace_trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut n = 0;
    for b in bytes {
        if !(b'0'..=b'9').contains(b) {
            return None;
        }
        n = n * 10 + u64::from(b - b'0');
    }
    Some(n)
}

fn lengths(a: [u8; 3], b: [u8; 3], joined: bool) {
    let headers = if joined {
        let mut value = a.to_vec();
        value.push(b',');
        value.extend_from_slice(&b);
        vec![header("Content-Length", &value)]
    } else {
        vec![header("Content-Length", &a), header("content-length", &b)]
    };
    let result = fields(&headers, Version::Http11).and_then(request_framing);
    // Arbitrary bytes, including all controls, signs, and invalid digits.
    // Outer whitespace in constructed fields is forbidden by fields.
    let canonical = headers.iter().all(|h| whitespace_trim(&h.value) == h.value);
    let mut expected = None;
    let mut valid = canonical;
    for raw in [&a[..], &b[..]] {
        for value in raw.split(|b| *b == b',') {
            match decimal(whitespace_trim(value)) {
                Some(n) => {
                    valid &= expected.is_none_or(|old| old == n);
                    expected = Some(n);
                }
                None => valid = false,
            }
        }
    }
    kani::cover!(valid);
    kani::cover!(!valid);
    if valid {
        let expected = Ok(Framing::Length(expected.unwrap()));
        assert_eq!(result, expected);
        let info = fields(&headers, Version::Http11).unwrap();
        let response = ResponseHead {
            version: Version::Http11,
            status: 200,
            reason: vec![],
            headers,
        };
        assert_eq!(response_framing(&response, info, Method::Other), expected);
    } else {
        assert!(result.is_err());
    }
}

#[kani::proof]
#[kani::unwind(24)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn content_lengths_have_one_value() {
    lengths(kani::any(), kani::any(), kani::any());
}

// A broken numeric reader that ignores all but the first digit. Distinct
// lengths with a shared leading digit then collapse to the same value.
fn first_digit(bytes: &[u8], radix: u32, error: Error) -> Result<u64, Error> {
    bytes
        .first()
        .and_then(|b| char::from(*b).to_digit(radix))
        .map(u64::from)
        .ok_or(error)
}

#[kani::proof]
#[kani::unwind(24)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(number, first_digit)]
fn content_lengths_control_truncated_number() {
    lengths(*b"100", *b"101", false);
}

fn transfer_fields(index: usize, with_length: bool, reversed: bool, old: bool, split: bool) {
    let variants: [&[u8]; 8] = [
        b"chunked",
        b"gzip",
        b"gzip, chunked",
        b"chunked, gzip",
        b"chunked, chunked",
        b"",
        b", ChUnKeD,",
        b"chunked;x=1",
    ];
    kani::assume(index < variants.len());
    let version = if old {
        Version::Http10
    } else {
        Version::Http11
    };
    let mut headers = if split && matches!(index, 2..=4) {
        let comma = variants[index].iter().position(|b| *b == b',').unwrap();
        vec![
            header("Transfer-Encoding", &variants[index][..comma]),
            header("transfer-encoding", trim(&variants[index][comma + 1..])),
        ]
    } else {
        vec![header("Transfer-Encoding", variants[index])]
    };
    if with_length {
        let length = header("Content-Length", b"0");
        if reversed {
            headers.insert(0, length);
        } else {
            headers.push(length);
        }
    }
    let result = fields(&headers, version).and_then(request_framing);
    kani::cover!(result.is_ok());
    kani::cover!(result.is_err());
    if with_length || old || !matches!(index, 0 | 6) {
        assert!(result.is_err());
    } else {
        assert_eq!(result, Ok(Framing::Chunked));
        let info = fields(&headers, version).unwrap();
        let response = ResponseHead {
            version,
            status: 200,
            reason: vec![],
            headers,
        };
        assert_eq!(response_framing(&response, info, Method::Other), result);
    }
}

#[kani::proof]
#[kani::unwind(32)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn transfer_fields_have_one_boundary() {
    transfer_fields(
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
}

// An unsafe alternative field policy: Content-Length takes precedence,
// otherwise any occurrence of chunked decides the boundary. It performs
// actual parsing, but drops the ambiguity checks of fields.
fn length_precedence(headers: &[Header], _: Version) -> Result<Fields, Error> {
    let mut info = Fields {
        length: None,
        transfer: false,
        chunked: false,
        unsupported_transfer_coding: false,
        close: false,
    };
    for h in headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            info.length = Some(number(&h.value, 10, Error::ContentLength)?);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            info.transfer = true;
            info.chunked |= h
                .value
                .split(|b| *b == b',')
                .any(|v| trim(v).eq_ignore_ascii_case(b"chunked"));
        }
    }
    if info.length.is_some() {
        info.transfer = false;
        info.chunked = false;
    }
    Ok(info)
}

#[kani::proof]
#[kani::unwind(32)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(fields, length_precedence)]
fn transfer_fields_control_length_precedence() {
    transfer_fields(0, true, false, false, false);
}

fn field_syntax(bytes: [u8; 4]) {
    // A complete field, without its line ending. This includes obs-fold,
    // bare CR/LF, whitespace before the colon, and every non-ASCII byte.
    let result = header_line(&bytes, false).and_then(|h| fields(&[h], Version::Http11));
    let colon = bytes.iter().position(|b| *b == b':');
    let allowed = colon.is_some_and(|n| {
        n > 0
            && bytes[..n]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
            && bytes[n + 1..]
                .iter()
                .all(|b| *b == 9 || (*b >= 32 && *b != 127))
    });
    kani::cover!(allowed);
    kani::cover!(!allowed);
    assert_eq!(result.is_ok(), allowed);
}

#[kani::proof]
#[kani::unwind(24)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn strict_head_fields_refuse_line_injection() {
    field_syntax(kani::any());
}

fn allow_controls(_: u8) -> bool {
    true
}

#[kani::proof]
#[kani::unwind(24)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(field_byte, allow_controls)]
fn strict_head_fields_control_allow_controls() {
    field_syntax(*b"X:\rx");
}

fn pipeline(n: usize, payload: [u8; 3]) {
    kani::assume(n <= 3);
    kani::cover!(n == 0);
    kani::cover!(n == 3);
    let head = b"POST / HTTP/1.1\r\nHost:a\r\nContent-Length:0\r\n\r\n";
    let following = b"GET /next HTTP/1.1\r\nHost:a\r\n\r\n";
    let mut storage = [0; 80];
    let head_end = head.len();
    storage[..head_end].copy_from_slice(head);
    storage[head_end - 5] = b'0' + n as u8;
    storage[head_end..head_end + n].copy_from_slice(&payload[..n]);
    let next = head_end + n;
    storage[next..next + following.len()].copy_from_slice(following);
    let wire = &storage[..next + following.len()];
    let mut decoder = RequestEvents::new();
    assert!(
        matches!(decoder.decode(&wire, false), Ok(Step::Item(Event::Head(_), used)) if used == head_end)
    );
    let mut used = head_end;
    if n > 0 {
        match decoder.decode(&wire[used..], false).unwrap() {
            Step::Item(Event::Body(body), count) => {
                assert_eq!(body, payload[..n]);
                assert_eq!(count, n);
                used += count;
            }
            _ => panic!("a length delimited body must end at its declared length"),
        }
    }
    assert!(matches!(
        decoder.decode(&wire[used..], false),
        Ok(Step::Item(Event::Done, 0))
    ));
    assert_eq!(used, next);
    assert!(
        matches!(decoder.decode(&wire[used..], false), Ok(Step::Item(Event::Head(head), count)) if head.target == "/next" && count == wire.len() - next)
    );
}

#[kani::proof]
#[kani::unwind(32)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn pipeline_starts_at_the_declared_boundary() {
    pipeline(kani::any(), kani::any());
}

// A framing bug that treats a declared body as empty consumes its bytes
// as the start of the following request instead.
fn ignore_length(_: Fields) -> Result<Framing, Error> {
    Ok(Framing::Empty)
}

#[kani::proof]
#[kani::unwind(32)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(request_framing, ignore_length)]
fn pipeline_control_ignore_length() {
    pipeline(1, *b"x..");
}

fn head_boundary(input: &[u8]) -> Result<Option<usize>, ()> {
    let mut start = 0;
    let mut first = true;
    for (i, byte) in input.iter().enumerate() {
        if *byte == b'\n' {
            if i == start || input[i - 1] != b'\r' || i - start > 9 {
                return Err(());
            }
            if !first && i - start == 1 {
                return Ok(Some(i + 1));
            }
            start = i + 1;
            first = false;
        }
    }
    if input.len() - start >= 10 {
        Err(())
    } else {
        Ok(None)
    }
}

fn head_lines(bytes: [u8; 10], len: usize, cut: usize) {
    kani::assume(len <= bytes.len());
    let input = &bytes[..len];
    let limits = Limits {
        start_line: 8,
        header_line: 8,
        head: 16,
        headers: 4,
        ..Limits::default()
    };
    let mut reader = Reader::new(limits);
    let expected = head_boundary(input);
    let got = reader.head(input).map_err(|_| ());
    kani::cover!(matches!(got, Ok(Some(_))));
    kani::cover!(got.is_err());
    kani::cover!(matches!(got, Ok(None)));
    assert_eq!(got, expected);
    kani::assume(cut <= len);
    let mut split = Reader::new(limits);
    let first = split.head(&input[..cut]).map_err(|_| ());
    if first == Ok(None) {
        assert_eq!(split.head(input).map_err(|_| ()), expected);
    } else {
        assert_eq!(first, expected);
    }
}

#[kani::proof]
#[kani::unwind(12)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn head_boundaries_require_crlf() {
    head_lines(kani::any(), kani::any(), kani::any());
}

// A lenient scanner that makes a bare LF a line ending. It can disagree
// with a strict peer on the end of a request head.
fn bare_lf_head(_: &mut Reader, input: &[u8]) -> Result<Option<usize>, Error> {
    let mut start = 0;
    let mut first = true;
    for (i, byte) in input.iter().enumerate() {
        if *byte == b'\n' {
            let content = input[start..i]
                .strip_suffix(b"\r")
                .unwrap_or(&input[start..i]);
            if content.len() > 8 {
                return Err(Error::HeaderLineTooLong);
            }
            if !first && content.is_empty() {
                return Ok(Some(i + 1));
            }
            start = i + 1;
            first = false;
        }
    }
    if input.len() - start >= 10 {
        Err(Error::HeaderLineTooLong)
    } else {
        Ok(None)
    }
}

#[kani::proof]
#[kani::unwind(12)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(Reader::head, bare_lf_head)]
fn head_boundaries_control_bare_lf() {
    head_lines(*b"X\n\n.......", 3, 0);
}
