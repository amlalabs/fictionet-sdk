//! Production head and borrowed body framing, supplementing the per-step
//! body proofs. Pipeline composition excludes owned request-head construction,
//! header-name routing and request-target validation.
//! Source: protocols/http1.rs scan_fields:1676, valid_field_value:1727,
//! content_length:1731, check_framing_fields:1742, transfer_encoding:1749,
//! complete_transfer:1771, request_framing:1778, response_framing:1791,
//! header_parts:1830, Reader::head:1391, RequestEvents::scan_request:857.
//! native.rs:202 constructs RequestEvents with the same strict framing core.
use super::*;

fn find_byte(x: u8, text: &[u8]) -> Option<usize> {
    text.iter().position(|b| *b == x)
}

// The production predicate searches a punctuation slice. The separate
// all-byte proof below establishes this loop-free equivalent before it is
// used compositionally in the larger head proofs.
fn token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
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

// A single-pass reference grammar: optional whitespace, digits, optional
// whitespace, then a comma or the end. It does not use the parser's split,
// trim, numeric conversion, or duplicate-value update.
fn decimal_list(bytes: &[u8]) -> Option<u64> {
    let mut expected = None;
    let mut number = 0;
    let mut phase = 0;
    for byte in bytes.iter().copied().chain(core::iter::once(b',')) {
        match byte {
            b'0'..=b'9' => {
                if phase == 2 {
                    return None;
                }
                phase = 1;
                number = number * 10 + u64::from(byte - b'0');
            }
            b' ' | b'\t' => {
                if phase == 1 {
                    phase = 2;
                }
            }
            b',' => {
                if phase == 0 || expected.is_some_and(|old| old != number) {
                    return None;
                }
                expected = Some(number);
                number = 0;
                phase = 0;
            }
            _ => return None,
        }
    }
    expected
}

// These proofs compose the production field-value validation and framing
// updates. Header-name routing remains in scan_fields and is exercised by
// the native server tests, rather than duplicated in these value proofs.
fn empty_fields() -> Fields {
    Fields {
        length: None,
        transfer: false,
        chunked: false,
        unsupported_transfer_coding: false,
        close: false,
    }
}

fn length_value(value: &[u8], info: &mut Fields) -> Result<(), Error> {
    if !valid_field_value(value) {
        return Err(Error::Header);
    }
    content_length(value, &mut info.length)
}

fn lengths(a: [u8; 3], b: [u8; 3], joined: bool) {
    let mut value = [0; 7];
    value[..3].copy_from_slice(&a);
    value[3] = b',';
    value[4..].copy_from_slice(&b);
    let mut info = empty_fields();
    let parsed = if joined {
        length_value(&value, &mut info)
    } else {
        length_value(&a, &mut info).and_then(|()| length_value(&b, &mut info))
    };
    let info = parsed.map(|()| info);
    let result = info.and_then(request_framing);
    // Outer whitespace in constructed fields is forbidden by fields.
    let canonical = if joined {
        whitespace_trim(&value) == value
    } else {
        whitespace_trim(&a) == a && whitespace_trim(&b) == b
    };
    let expected = decimal_list(&value);
    let valid = canonical && expected.is_some();
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
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn content_lengths_separate_have_one_value() {
    lengths(kani::any(), kani::any(), false);
}

#[kani::proof]
#[kani::unwind(10)]
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
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(number, first_digit)]
fn content_lengths_control_truncated_number() {
    lengths(*b"100", *b"101", false);
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(number, first_digit)]
fn content_lengths_joined_control_truncated_number() {
    lengths(*b"100", *b"101", true);
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
    // The boolean identifies the already classified Content-Length field.
    // Keep both input orders and both separate/joined coding representations.
    let mut headers = [(false, &[][..]); 3];
    let mut count = if split && matches!(index, 2..=4) {
        let comma = variants[index].iter().position(|b| *b == b',').unwrap();
        headers[0] = (false, &variants[index][..comma]);
        headers[1] = (false, trim(&variants[index][comma + 1..]));
        2
    } else {
        headers[0] = (false, variants[index]);
        1
    };
    if with_length {
        let length = (true, &b"0"[..]);
        if reversed {
            headers[2] = headers[1];
            headers[1] = headers[0];
            headers[0] = length;
        } else {
            headers[count] = length;
        }
        count += 1;
    }
    let info = (|| {
        check_framing_fields(true, with_length)?;
        let mut info = empty_fields();
        for (length, value) in &headers[..count] {
            if !valid_field_value(value) {
                return Err(Error::Header);
            }
            if *length {
                content_length(value, &mut info.length)?;
            } else {
                transfer_encoding(value, version, &mut info)?;
            }
        }
        complete_transfer(true, &info)?;
        Ok(info)
    })();
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
        #[kani::unwind(18)]
        #[kani::stub(core::slice::memchr::memchr, find_byte)]
        #[kani::stub(ascii::is_tchar, token_char)]
        fn $name() {
            // Every combination of Content-Length, its position, HTTP/1.0 and split
            // fields, one at a time: concrete flags keep the solver small.
            for flags in 0u8..16 {
                transfer_fields(
                    $form,
                    flags & 1 != 0,
                    flags & 2 != 0,
                    flags & 4 != 0,
                    flags & 8 != 0,
                );
            }
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

// Omitting the coexistence guard lets conflicting fields reach the normal
// parser, which then chooses transfer framing despite a declared length.
fn allow_conflicting_fields(_: bool, _: bool) -> Result<(), Error> {
    Ok(())
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(check_framing_fields, allow_conflicting_fields)]
fn transfer_fields_control_conflicting_fields() {
    transfer_fields(0, true, false, false, false);
}

// A negative-only copy of the coding update with independently omitted
// version and ordering guards. Token parsing and state updates are unchanged.
fn relaxed_transfer(
    value: &[u8],
    version: Version,
    result: &mut Fields,
    allow_old: bool,
    allow_after_chunked: bool,
) -> Result<(), Error> {
    if !allow_old && version == Version::Http10 {
        return Err(Error::Http10TransferEncoding);
    }
    for value in value.split(|b| *b == b',') {
        let value = trim(value);
        if value.is_empty() {
            continue;
        }
        if !allow_after_chunked && result.chunked {
            return Err(Error::ChunkedNotLast);
        }
        if !token(value) {
            return Err(Error::TransferEncoding);
        }
        result.transfer = true;
        result.chunked = value.eq_ignore_ascii_case(b"chunked");
        result.unsupported_transfer_coding |= !result.chunked;
    }
    Ok(())
}

fn allow_old_transfer(value: &[u8], version: Version, result: &mut Fields) -> Result<(), Error> {
    relaxed_transfer(value, version, result, true, false)
}

fn allow_later_coding(value: &[u8], version: Version, result: &mut Fields) -> Result<(), Error> {
    relaxed_transfer(value, version, result, false, true)
}

fn allow_unsupported_coding(info: Fields) -> Result<Framing, Error> {
    if info.transfer {
        if !info.chunked {
            return Err(Error::RequestTransferEncoding);
        }
        Ok(Framing::Chunked)
    } else {
        Ok(info.length.map_or(Framing::Empty, Framing::Length))
    }
}

// Missing final chunked and unsupported coding independently reject gzip.
// This paired ablation removes both rejection rules, leaving the actual
// field parser to establish the transfer-coding state.
fn allow_any_transfer_framing(info: Fields) -> Result<Framing, Error> {
    Ok(if info.transfer {
        Framing::Chunked
    } else {
        info.length.map_or(Framing::Empty, Framing::Length)
    })
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(transfer_encoding, allow_old_transfer)]
fn transfer_fields_control_old_version() {
    transfer_fields(0, false, false, true, false);
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(request_framing, allow_unsupported_coding)]
fn transfer_fields_control_unsupported_coding() {
    transfer_fields(2, false, false, false, false);
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(request_framing, allow_any_transfer_framing)]
fn transfer_fields_control_missing_final_chunked() {
    transfer_fields(1, false, false, false, false);
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(transfer_encoding, allow_later_coding)]
fn transfer_fields_control_repeated_chunked() {
    transfer_fields(4, false, false, false, true);
}

// Nonfinal chunked is also rejected by the final-coding and unsupported
// checks, so accepting chunked followed by gzip requires a paired ablation.
#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(transfer_encoding, allow_later_coding)]
#[kani::stub(request_framing, allow_any_transfer_framing)]
fn transfer_fields_control_nonfinal_chunked() {
    transfer_fields(3, false, false, false, true);
}

fn transfer_value_grammar(bytes: [u8; 8], len: usize) {
    kani::assume(len <= bytes.len());
    let value = &bytes[..len];
    let mut info = empty_fields();
    let result = (|| {
        if !valid_field_value(value) {
            return Err(Error::Header);
        }
        transfer_encoding(value, Version::Http11, &mut info)?;
        complete_transfer(true, &info)?;
        request_framing(info)
    })();
    // Within eight bytes, the only canonical accepted values are chunked
    // and chunked with one empty comma element before or after it. Any OWS
    // at the outside is noncanonical; internal OWS needs at least nine bytes.
    let start = usize::from(len == 8 && bytes[0] == b',');
    let shape = len == 7 || len == 8 && (bytes[0] == b',' || bytes[7] == b',');
    let mut spelling = true;
    for (i, expected) in b"chunked".iter().enumerate() {
        spelling &= bytes[start + i].to_ascii_lowercase() == *expected;
    }
    let accepted = shape && spelling;
    kani::cover!(accepted);
    kani::cover!(!accepted);
    if accepted {
        assert!(result == Ok(Framing::Chunked));
    } else {
        assert!(result.is_err());
    }
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
fn transfer_values_follow_bounded_grammar() {
    transfer_value_grammar(kani::any(), kani::any());
}

// The same paired removal of the final-coding and unsupported checks
// must also violate the arbitrary-byte grammar property.
#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(request_framing, allow_any_transfer_framing)]
fn transfer_values_control_missing_final_chunked() {
    transfer_value_grammar(*b"gzip....", 4);
}

fn field_syntax(bytes: [u8; 4]) {
    // A complete field, without its line ending. This includes obs-fold,
    // bare CR/LF, whitespace before the colon, and every non-ASCII byte.
    let result = header_parts(&bytes, false).is_ok_and(|(name, value)| valid_field(name, value));
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
        #[kani::unwind(8)]
        #[kani::stub(core::slice::memchr::memchr, find_byte)]
        #[kani::stub(ascii::is_tchar, token_char)]
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
#[kani::unwind(8)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
fn strict_head_fields_without_colon() {
    let bytes: [u8; 4] = kani::any();
    kani::assume(bytes.iter().all(|b| *b != b':'));
    field_syntax(bytes);
}

fn allow_controls(_: u8) -> bool {
    true
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(field_byte, allow_controls)]
fn strict_head_fields_control_allow_controls() {
    field_syntax(*b"X:\rx");
}

// `Reader` only splits lines; the start line and field names are checked by
// `scan_request`, outside this proof. The heads are therefore the shortest
// the reader accepts, a start line `P` and one field `L:<n>` whose digit goes
// through the production `content_length`, then a second head `G`. Short
// lines keep the solver inside the memory cap; the body bytes are arbitrary.
const PIPELINE_HEAD: usize = 10;

fn pipeline<const N: usize>(payload: [u8; 3]) {
    assert!(N <= 3);
    let mut bytes = [0u8; PIPELINE_HEAD + 3 + 5];
    bytes[..PIPELINE_HEAD].copy_from_slice(b"P\r\nL:0\r\n\r\n");
    bytes[5] = b'0' + N as u8;
    bytes[PIPELINE_HEAD..PIPELINE_HEAD + N].copy_from_slice(&payload[..N]);
    let next = PIPELINE_HEAD + N;
    bytes[next..next + 5].copy_from_slice(b"G\r\n\r\n");
    let wire = &bytes[..next + 5];
    let mut reader = Reader::new(Limits::default());
    assert_eq!(reader.head(wire), Ok(Some(PIPELINE_HEAD)));
    let mut info = empty_fields();
    content_length(&wire[5..6], &mut info.length).expect("valid declared length");
    let framing = request_framing(info).expect("valid request framing");
    reader.begin(framing, false);
    let mut used = PIPELINE_HEAD;
    if N > 0 {
        match reader.body::<()>(&wire[used..], false, false) {
            Ok(Some(Step::Item(BorrowedEvent::Body(body), count))) => {
                assert!(body == &payload[..N]);
                assert!(count == N);
                used += count;
            }
            _ => panic!("a length delimited body must end at its declared length"),
        }
    }
    assert!(matches!(
        reader.body::<()>(&wire[used..], false, false),
        Ok(Some(Step::Item(BorrowedEvent::Done, 0)))
    ));
    assert!(used == next);
    assert!(matches!(
        reader.body::<()>(&wire[used..], false, false),
        Ok(None)
    ));
    assert_eq!(reader.head(&wire[used..]), Ok(Some(5)));
}

macro_rules! pipeline_proof {
    ($name:ident, $length:expr) => {
        #[kani::proof]
        #[kani::unwind(12)]
        #[kani::stub(core::slice::memchr::memchr, find_byte)]
        fn $name() {
            pipeline::<$length>(kani::any());
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
#[kani::unwind(12)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
#[kani::stub(request_framing, ignore_length)]
fn pipeline_control_ignore_length() {
    pipeline::<1>(*b"x..");
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
    ($name:ident, $length:expr, $bound:literal) => {
        #[kani::proof]
        #[kani::unwind($bound)]
        #[kani::stub(core::slice::memchr::memchr, find_byte)]
        #[kani::stub(ascii::is_tchar, token_char)]
        fn $name() {
            head_lines(kani::any(), $length, kani::any());
        }
    };
}
head_proof!(head_boundaries_length_zero, 0, 6);
head_proof!(head_boundaries_length_one, 1, 6);
head_proof!(head_boundaries_length_two, 2, 6);
head_proof!(head_boundaries_length_three, 3, 6);
head_proof!(head_boundaries_length_four, 4, 6);
head_proof!(head_boundaries_length_five, 5, 8);
head_proof!(head_boundaries_length_six, 6, 8);
head_proof!(head_boundaries_length_seven, 7, 12);
head_proof!(head_boundaries_length_eight, 8, 10);
head_proof!(head_boundaries_length_nine, 9, 12);
head_proof!(head_boundaries_length_ten, 10, 12);

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
#[kani::stub(ascii::is_tchar, token_char)]
#[kani::stub(Reader::head, bare_lf_head)]
fn head_boundaries_control_bare_lf() {
    head_lines(*b"X\n\n.......", 3, 0);
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(core::slice::memchr::memchr, find_byte)]
fn token_character_matches_production() {
    let byte: u8 = kani::any();
    assert_eq!(ascii::is_tchar(byte), token_char(byte));
}

fn allow_token_byte(_: u8) -> bool {
    true
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(ascii::is_tchar, allow_token_byte)]
fn token_character_control_allow_invalid() {
    token_character_matches_production();
}
