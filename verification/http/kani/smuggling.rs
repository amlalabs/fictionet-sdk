//! Production head framing, supplementing the per-step body proofs.
//! Source: protocols/http1.rs scan_fields:1676, request_framing:1753,
//! response_framing:1766, header_parts:1805, RequestEvents::scan_request:857.
//! fields and header_line delegate to these borrowed parsers before copying.
//! native.rs:202 constructs RequestEvents with strict chunk framing.
use super::*;

fn find_byte(x: u8, text: &[u8]) -> Option<usize> {
    text.iter().position(|b| *b == x)
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
    let mut value = [0; 7];
    value[..3].copy_from_slice(&a);
    value[3] = b',';
    value[4..].copy_from_slice(&b);
    let headers = if joined {
        [("Content-Length", &value[..]), ("", &[][..])]
    } else {
        [("Content-Length", &a[..]), ("content-length", &b[..])]
    };
    let headers = &headers[..if joined { 1 } else { 2 }];
    let info = scan_fields(headers.iter().copied(), Version::Http11);
    let result = info.and_then(request_framing);
    // Arbitrary bytes, including all controls, signs, and invalid digits.
    // Outer whitespace in constructed fields is forbidden by fields.
    let canonical = headers
        .iter()
        .all(|(_, value)| whitespace_trim(value) == *value);
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
        assert!(result == expected);
        let info = match info {
            Ok(info) => info,
            Err(_) => panic!("accepted fields must have framing"),
        };
        let response = ResponseHead {
            version: Version::Http11,
            status: 200,
            reason: vec![],
            headers: vec![],
        };
        assert!(response_framing(&response, info, Method::Other) == expected);
    } else {
        assert!(result.is_err());
    }
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn content_lengths_separate_have_one_value() {
    lengths(kani::any(), kani::any(), false);
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn content_lengths_joined_have_one_value() {
    lengths(kani::any(), kani::any(), true);
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
#[kani::unwind(16)]
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
    let mut headers = [("", &[][..]); 3];
    let mut count = if split && matches!(index, 2..=4) {
        let comma = variants[index].iter().position(|b| *b == b',').unwrap();
        headers[0] = ("Transfer-Encoding", &variants[index][..comma]);
        headers[1] = ("transfer-encoding", trim(&variants[index][comma + 1..]));
        2
    } else {
        headers[0] = ("Transfer-Encoding", variants[index]);
        1
    };
    if with_length {
        let length = ("Content-Length", &b"0"[..]);
        if reversed {
            headers[2] = headers[1];
            headers[1] = headers[0];
            headers[0] = length;
        } else {
            headers[count] = length;
        }
        count += 1;
    }
    let info = scan_fields(headers[..count].iter().copied(), version);
    let result = info.and_then(request_framing);
    kani::cover!(result.is_ok());
    kani::cover!(result.is_err());
    if with_length || old || !matches!(index, 0 | 6) {
        assert!(result.is_err());
    } else {
        assert!(result == Ok(Framing::Chunked));
        let info = match info {
            Ok(info) => info,
            Err(_) => panic!("accepted fields must have framing"),
        };
        let response = ResponseHead {
            version,
            status: 200,
            reason: vec![],
            headers: vec![],
        };
        assert!(response_framing(&response, info, Method::Other) == result);
    }
}

macro_rules! transfer_proof {
    ($name:ident, $form:expr) => {
        #[kani::proof]
        #[kani::unwind(20)]
        #[kani::stub(core::slice::memchr::memchr, find_byte)]
        fn $name() {
            transfer_fields($form, kani::any(), kani::any(), kani::any(), kani::any());
        }
    };
}
transfer_proof!(transfer_fields_chunked, 0);
transfer_proof!(transfer_fields_gzip, 1);
transfer_proof!(transfer_fields_gzip_then_chunked, 2);
transfer_proof!(transfer_fields_chunked_then_gzip, 3);
transfer_proof!(transfer_fields_repeated_chunked, 4);
transfer_proof!(transfer_fields_empty, 5);
transfer_proof!(transfer_fields_empty_elements, 6);
transfer_proof!(transfer_fields_parameters, 7);

// An unsafe alternative field policy: Content-Length takes precedence,
// otherwise any occurrence of chunked decides the boundary. It performs
// actual parsing, but drops the ambiguity checks of fields.
fn length_precedence<'a>(
    headers: impl Iterator<Item = (&'a str, &'a [u8])> + Clone,
    _: Version,
) -> Result<Fields, Error> {
    let mut info = Fields {
        length: None,
        transfer: false,
        chunked: false,
        unsupported_transfer_coding: false,
        close: false,
    };
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            info.length = Some(number(value, 10, Error::ContentLength)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            info.transfer = true;
            info.chunked |= value
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
#[kani::unwind(20)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(scan_fields, length_precedence)]
fn transfer_fields_control_length_precedence() {
    transfer_fields(0, true, false, false, false);
}

fn field_syntax(bytes: [u8; 4]) {
    // A complete field, without its line ending. This includes obs-fold,
    // bare CR/LF, whitespace before the colon, and every non-ASCII byte.
    let result = header_parts(&bytes, false).is_ok_and(|(name, value)| {
        assert!(name.len() <= 3);
        assert!(!name.eq_ignore_ascii_case("content-length"));
        assert!(!name.eq_ignore_ascii_case("transfer-encoding"));
        assert!(!name.eq_ignore_ascii_case("connection"));
        valid_field(name, value)
    });
    let colon = bytes.iter().position(|b| *b == b':');
    let allowed = colon.is_some_and(|n| {
        n > 0
            && bytes[..n].iter().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
            && bytes[n + 1..]
                .iter()
                .all(|b| *b == 9 || (*b >= 32 && *b != 127))
    });
    kani::cover!(allowed);
    kani::cover!(!allowed);
    assert!(result == allowed);
}

macro_rules! field_proof {
    ($name:ident, $colon:expr) => {
        #[kani::proof]
        #[kani::unwind(16)]
        #[kani::stub(core::slice::memchr::memchr, find_byte)]
        fn $name() {
            let mut bytes: [u8; 4] = kani::any();
            bytes[$colon] = b':';
            for byte in &bytes[..$colon] {
                kani::assume(*byte != b':');
            }
            field_syntax(bytes);
        }
    };
}
field_proof!(strict_head_fields_empty_name, 0);
field_proof!(strict_head_fields_one_byte_name, 1);
field_proof!(strict_head_fields_two_byte_name, 2);
field_proof!(strict_head_fields_three_byte_name, 3);

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn strict_head_fields_without_colon() {
    let bytes: [u8; 4] = kani::any();
    kani::assume(bytes.iter().all(|b| *b != b':'));
    field_syntax(bytes);
}

fn allow_controls(_: u8) -> bool {
    true
}

#[kani::proof]
#[kani::unwind(16)]
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
        match decoder.decode(&wire[used..], false) {
            Ok(Step::Item(Event::Body(body), count)) => {
                assert!(body == payload[..n]);
                assert!(count == n);
                used += count;
            }
            _ => panic!("a length delimited body must end at its declared length"),
        }
    }
    assert!(matches!(
        decoder.decode(&wire[used..], false),
        Ok(Step::Item(Event::Done, 0))
    ));
    assert!(used == next);
    assert!(
        matches!(decoder.decode(&wire[used..], false), Ok(Step::Item(Event::Head(head), count)) if head.target == "/next" && count == wire.len() - next)
    );
}

macro_rules! pipeline_proof {
    ($name:ident, $length:expr) => {
        #[kani::proof]
        #[kani::unwind(24)]
        #[kani::stub(core::slice::memchr::memchr, find_byte)]
        fn $name() {
            pipeline($length, kani::any());
        }
    };
}
pipeline_proof!(pipeline_boundary_empty_body, 0);
pipeline_proof!(pipeline_boundary_one_byte, 1);
pipeline_proof!(pipeline_boundary_two_bytes, 2);
pipeline_proof!(pipeline_boundary_three_bytes, 3);

// A framing bug that treats a declared body as empty consumes its bytes
// as the start of the following request instead.
fn ignore_length(_: Fields) -> Result<Framing, Error> {
    Ok(Framing::Empty)
}

#[kani::proof]
#[kani::unwind(24)]
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
    kani::assume(cut <= len);
    let mut reader = Reader::new(limits);
    let expected = head_boundary(input);
    let first = reader.head(&input[..cut]).map_err(|_| ());
    let got = if first == Ok(None) {
        reader.head(input).map_err(|_| ())
    } else {
        first
    };
    // The cut at zero includes an unsplit scan for every input, so this
    // single comparison proves both the grammar and split independence.
    kani::cover!(matches!(got, Ok(Some(_))));
    kani::cover!(got.is_err());
    kani::cover!(matches!(got, Ok(None)));
    assert!(got == expected);
}

macro_rules! head_proof {
    ($name:ident, $length:expr) => {
        #[kani::proof]
        #[kani::unwind(12)]
        #[kani::stub(core::slice::memchr::memchr, find_byte)]
        fn $name() {
            head_lines(kani::any(), $length, kani::any());
        }
    };
}
head_proof!(head_boundaries_length_zero, 0);
head_proof!(head_boundaries_length_one, 1);
head_proof!(head_boundaries_length_two, 2);
head_proof!(head_boundaries_length_three, 3);
head_proof!(head_boundaries_length_four, 4);
head_proof!(head_boundaries_length_five, 5);
head_proof!(head_boundaries_length_six, 6);
head_proof!(head_boundaries_length_seven, 7);
head_proof!(head_boundaries_length_eight, 8);
head_proof!(head_boundaries_length_nine, 9);
head_proof!(head_boundaries_length_ten, 10);

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
