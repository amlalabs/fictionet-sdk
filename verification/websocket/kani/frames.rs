//! Bounded checks of the production WebSocket codec. Source mappings and
//! mutation controls are recorded in the adjacent README.
use super::*;

fn headers_follow_wire_grammar(bytes: [u8; 14], n: usize) {
    kani::assume(n <= bytes.len());
    let b = &bytes[..n];
    let got = Header::parse(b);
    let mut expected = None;
    let mut invalid = false;
    if n > 0 {
        let op = bytes[0] & 15;
        let control = op >= 8;
        invalid = bytes[0] & 0x70 != 0
            || !matches!(op, 0 | 1 | 2 | 8 | 9 | 10)
            || control && bytes[0] & 0x80 == 0;
        if n > 1 {
            let tag = bytes[1] & 127;
            invalid |= control && tag > 125;
            let width = match tag {
                126 => 2,
                127 => 8,
                _ => 0,
            };
            if n >= 2 + width {
                let mut len = if width == 0 { u64::from(tag) } else { 0 };
                for i in 0..width {
                    len = (len << 8) | u64::from(bytes[2 + i]);
                }
                invalid |= (width == 2 && len < 126)
                    || (width == 8 && (len < 65536 || len >= 1 << 63))
                    || len > MAX_PAYLOAD as u64;
                let masked = bytes[1] >= 128;
                let header_len = 2 + width + if masked { 4 } else { 0 };
                if n >= header_len {
                    expected = Some((len as usize, header_len, masked));
                }
            }
        }
    }
    if invalid {
        assert!(got.is_err());
    } else {
        assert_eq!(
            got.as_ref()
                .ok()
                .map(|h| h.map(|h| (h.len, h.header_len, h.mask.is_some()))),
            Some(expected)
        );
    }
    if let Ok(Some(h)) = got {
        assert_eq!(h.fin, bytes[0] & 128 != 0);
        assert_eq!(h.opcode.to_u8(), bytes[0] & 15);
        assert_eq!(h.frame_len(), h.header_len + h.len);
        if let Some(key) = h.mask {
            assert_eq!(&key, &bytes[h.header_len - 4..h.header_len]);
        }
        for side in [Side::Client, Side::Server] {
            let accepted = Frames::for_receiver(side).header(b);
            assert_eq!(accepted.is_ok(), h.mask.is_some() == (side == Side::Server));
        }
    }
}

#[kani::proof]
#[kani::unwind(16)]
fn websocket_headers_follow_wire_grammar() {
    headers_follow_wire_grammar(kani::any(), kani::any());
}

fn mask_is_involution_and_composes(original: [u8; 8], key: [u8; 4], offset: usize, cut: usize) {
    kani::assume(cut <= original.len());
    let mut whole = original;
    apply_mask(&mut whole, key, offset);
    for i in 0..8 {
        assert_eq!(whole[i], original[i] ^ key[(offset % 4 + i) % 4]);
    }
    let mut split = original;
    apply_mask(&mut split[..cut], key, offset);
    apply_mask(&mut split[cut..], key, offset.wrapping_add(cut));
    assert_eq!(split, whole);
    apply_mask(&mut whole, key, offset);
    assert_eq!(whole, original);
}

#[kani::proof]
#[kani::unwind(10)]
fn websocket_mask_is_involution_and_composes() {
    mask_is_involution_and_composes(kani::any(), kani::any(), kani::any(), kani::any());
}

fn exact_frame_boundary(bytes: [u8; 18], n: usize) {
    kani::assume(n <= bytes.len());
    let input = &bytes[..n];
    let parsed = Header::parse(input);
    let exact = Header::parse_exact(input);
    match parsed {
        Err(error) => assert_eq!(exact, Err(error)),
        Ok(None) => assert_eq!(exact, Err(Error::Truncated)),
        Ok(Some(header)) => {
            let end = header.header_len + header.len;
            if end < n {
                assert_eq!(exact, Err(Error::Trailing));
            } else if end > n {
                assert_eq!(exact, Err(Error::Truncated));
            } else {
                assert_eq!(exact, Ok(header));
                let payload = header.payload(input).expect("complete payload");
                assert_eq!(payload.len(), header.len);
                for i in 0..payload.len() {
                    assert_eq!(payload[i], input[header.header_len + i]);
                }
            }
        }
    }
}

#[kani::proof]
#[kani::unwind(20)]
fn websocket_exact_frame_boundaries() {
    exact_frame_boundary(kani::any(), kani::any());
}

fn accept_trailing(bytes: &[u8]) -> Result<Header, Error> {
    Header::parse(bytes)?.ok_or(Error::Truncated)
}

fn include_header(_: Header, bytes: &[u8]) -> Option<&[u8]> {
    Some(bytes)
}

#[kani::proof]
#[kani::unwind(20)]
#[kani::stub(Header::parse_exact, accept_trailing)]
fn websocket_control_without_exact_end() {
    let mut bytes = [0; 18];
    bytes[0] = 0x82;
    exact_frame_boundary(bytes, 3);
}

#[kani::proof]
#[kani::unwind(20)]
#[kani::stub(Header::payload, include_header)]
fn websocket_control_without_payload_start() {
    let mut bytes = [0; 18];
    bytes[0] = 0x82;
    exact_frame_boundary(bytes, 2);
}

fn small_frame_wire<const N: usize, const MASKED: bool>(
    data: [u8; 4],
    fin: bool,
    key: [u8; 4],
) -> ([u8; 10], usize) {
    kani::assume(N <= data.len());
    let header_len = if MASKED { 6 } else { 2 };
    let mut expected = [0u8; 10];
    expected[0] = (if fin { 128 } else { 0 }) | 2;
    expected[1] = (if MASKED { 128 } else { 0 }) | N as u8;
    if MASKED {
        expected[2..6].copy_from_slice(&key);
    }
    for i in 0..N {
        expected[header_len + i] = data[i] ^ if MASKED { key[i % 4] } else { 0 };
    }
    (expected, header_len + N)
}

fn small_frames_write<const N: usize, const MASKED: bool>(data: [u8; 4], fin: bool, key: [u8; 4]) {
    let (expected, len) = small_frame_wire::<N, MASKED>(data, fin, key);
    let mut wire = Vec::new();
    let Ok(()) = write_frame(
        &mut wire,
        fin,
        Opcode::Binary,
        MASKED.then_some(key),
        &data[..N],
    ) else {
        panic!("valid frame must encode");
    };
    assert!(wire.as_slice() == &expected[..len]);
}

fn small_frames_read<const N: usize, const MASKED: bool>(data: [u8; 4], fin: bool, key: [u8; 4]) {
    let (expected, len) = small_frame_wire::<N, MASKED>(data, fin, key);
    let header = Header::parse_exact(&expected[..len]).expect("valid frame header");
    let Some(decoded) = Frame::from_header(&expected[..len], header) else {
        panic!("valid frame must decode");
    };
    assert!(decoded.fin == fin);
    assert!(decoded.opcode == Opcode::Binary);
    assert!(decoded.mask == MASKED.then_some(key));
    assert!(decoded.payload.as_slice() == &data[..N]);
}

macro_rules! frame_case {
    ($write:ident, $read:ident, $len:expr, $masked:expr) => {
        #[kani::proof]
        #[kani::unwind(12)]
        fn $write() {
            small_frames_write::<$len, $masked>(kani::any(), kani::any(), kani::any());
        }
        #[kani::proof]
        #[kani::unwind(12)]
        fn $read() {
            small_frames_read::<$len, $masked>(kani::any(), kani::any(), kani::any());
        }
    };
}
frame_case!(
    websocket_small_frames_write_unmasked_zero,
    websocket_small_frames_read_unmasked_zero,
    0,
    false
);
frame_case!(
    websocket_small_frames_write_unmasked_one,
    websocket_small_frames_read_unmasked_one,
    1,
    false
);
frame_case!(
    websocket_small_frames_write_unmasked_two,
    websocket_small_frames_read_unmasked_two,
    2,
    false
);
frame_case!(
    websocket_small_frames_write_unmasked_three,
    websocket_small_frames_read_unmasked_three,
    3,
    false
);
frame_case!(
    websocket_small_frames_write_unmasked_four,
    websocket_small_frames_read_unmasked_four,
    4,
    false
);
frame_case!(
    websocket_small_frames_write_masked_zero,
    websocket_small_frames_read_masked_zero,
    0,
    true
);
frame_case!(
    websocket_small_frames_write_masked_one,
    websocket_small_frames_read_masked_one,
    1,
    true
);
frame_case!(
    websocket_small_frames_write_masked_two,
    websocket_small_frames_read_masked_two,
    2,
    true
);
frame_case!(
    websocket_small_frames_write_masked_three,
    websocket_small_frames_read_masked_three,
    3,
    true
);
frame_case!(
    websocket_small_frames_write_masked_four,
    websocket_small_frames_read_masked_four,
    4,
    true
);

fn close_codes_follow_wire_ranges(code: u16) {
    let allowed = (1000 <= code && code <= 1003)
        || (1007 <= code && code <= 1014)
        || (3000 <= code && code <= 4999);
    assert_eq!(Close::parse(&code.to_be_bytes()).is_ok(), allowed);
    assert_eq!(Close::new(code).to_bytes().is_ok(), allowed);
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_close_codes_follow_wire_ranges() {
    close_codes_follow_wire_ranges(kani::any());
}

fn text_across_fragment_boundary(bytes: [u8; 4], cut: usize) {
    kani::assume(cut <= bytes.len());
    let mut checked = 0;
    let first = validate_text(&bytes[..cut], &mut checked, false);
    assert!(checked <= cut);
    let result = first.and_then(|()| validate_text(&bytes, &mut checked, true));
    assert_eq!(result.is_ok(), core::str::from_utf8(&bytes).is_ok());
    if result.is_ok() {
        assert_eq!(checked, bytes.len());
    } else {
        assert_eq!(result, Err(Error::InvalidUtf8));
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_text_across_fragment_boundary() {
    text_across_fragment_boundary(kani::any(), kani::any());
}

fn message_limit_precedes_payload_copy(held: usize, limit: usize, next: u8) {
    kani::assume(held <= limit && limit <= 3 && next <= 125);
    let mut decoder = Messages::for_receiver(Side::Client).with_limit(limit);
    decoder.partial = Some(Partial {
        opcode: Opcode::Binary,
        data: vec![0; held],
        checked: 0,
    });
    let result = decoder.check_header(&[0x80, next]);
    if held + usize::from(next) > limit {
        assert_eq!(result, Err(Error::TooBig));
        assert_eq!(decoder.partial.as_ref().unwrap().data.len(), held);
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_message_limit_precedes_payload_copy() {
    message_limit_precedes_payload_copy(kani::any(), kani::any(), kani::any());
}

fn fragment_order(partial: bool, first: u8, len: u8) {
    kani::assume(len <= 125);
    let mut decoder = Messages::for_receiver(Side::Client);
    if partial {
        decoder.partial = Some(Partial {
            opcode: Opcode::Text,
            data: Vec::new(),
            checked: 0,
        });
    }
    let input = [first, len];
    let result = decoder.check_header(&input);
    let Ok(Some(header)) = Header::parse(&input) else {
        assert!(result.is_err());
        return;
    };
    // Continuation only inside a message, a new data frame only outside one,
    // and control frames in either state.
    match header.opcode {
        Opcode::Continuation if !partial => {
            assert_eq!(result, Err(Error::UnexpectedContinuation))
        }
        Opcode::Text | Opcode::Binary if partial => {
            assert_eq!(result, Err(Error::ExpectedContinuation))
        }
        _ => assert_eq!(result, Ok(())),
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_fragments_follow_message_order() {
    fragment_order(kani::any(), kani::any(), kani::any());
}

// The pre-copy guard with the order check removed: only size checks remain.
fn check_size_only(messages: &Messages, input: &[u8]) -> Result<(), Error> {
    messages.frames.header(input).map(|_| ())
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(Messages::check_header, check_size_only)]
fn websocket_control_without_fragment_order() {
    fragment_order(false, 0x80, 0);
}

fn ignore_control_kind(_: Opcode) -> bool {
    false
}
fn omit_mask(_: &mut [u8], _: [u8; 4], _: usize) {}
fn allow_every_close(_: u16) -> bool {
    true
}
fn omit_held(_: &Messages) -> usize {
    0
}
fn omit_direction(_: &Frames, input: &[u8]) -> Result<Option<Header>, Error> {
    Header::parse(input)
}
fn omit_payload_mask(b: &[u8], h: Header) -> Option<Frame> {
    Some(Frame {
        fin: h.fin,
        opcode: h.opcode,
        mask: h.mask,
        payload: b.get(h.header_len..h.frame_len())?.to_vec(),
    })
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(Opcode::is_control, ignore_control_kind)]
fn websocket_control_without_control_rules() {
    let mut bytes = [0; 14];
    bytes[0] = 0x09;
    headers_follow_wire_grammar(bytes, 2);
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(Opcode::is_control, ignore_control_kind)]
fn websocket_control_without_control_size() {
    let mut bytes = [0; 14];
    bytes[..4].copy_from_slice(&[0x89, 126, 0, 126]);
    headers_follow_wire_grammar(bytes, 4);
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(Frames::header, omit_direction)]
fn websocket_control_without_mask_direction() {
    websocket_headers_follow_wire_grammar();
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(apply_mask, omit_mask)]
fn websocket_control_without_masking() {
    websocket_mask_is_involution_and_composes();
}

#[kani::proof]
#[kani::unwind(12)]
#[kani::stub(Frame::from_header, omit_payload_mask)]
fn websocket_control_without_unmasking() {
    small_frames_read::<4, true>([1, 2, 3, 4], true, [1, 2, 3, 4]);
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(close_code::is_sendable, allow_every_close)]
fn websocket_control_without_close_ranges() {
    close_codes_follow_wire_ranges(1005);
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(Messages::held, omit_held)]
fn websocket_control_without_held_charge() {
    message_limit_precedes_payload_copy(1, 1, 1);
}

// Refusing every incomplete prefix loses characters split across frames.
fn validate_fragment_alone(data: &[u8], checked: &mut usize, _: bool) -> Result<(), Error> {
    core::str::from_utf8(data).map_err(|_| Error::InvalidUtf8)?;
    *checked = data.len();
    Ok(())
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(validate_text, validate_fragment_alone)]
fn websocket_control_without_utf8_carry() {
    text_across_fragment_boundary([0xe2, 0x82, 0xac, b'a'], 1);
}

#[kani::proof]
#[kani::unwind(16)]
fn websocket_writer_uses_minimal_length() {
    let len: usize = kani::any();
    kani::assume(len <= MAX_PAYLOAD);
    let mask: Option<[u8; 4]> = kani::any();
    let fin: bool = kani::any();
    let mut bytes = Vec::new();
    write_header(&mut bytes, fin, Opcode::Binary, mask, len);
    let parsed = Header::parse(&bytes);
    assert!(
        parsed.is_ok(),
        "written header must satisfy the wire grammar"
    );
    let header = parsed.unwrap().unwrap();
    assert_eq!(header.len, len);
    assert_eq!(header.fin, fin);
    assert_eq!(header.mask, mask);
    assert_eq!(header.header_len, bytes.len());
    assert_eq!(
        bytes[1] & 127,
        if len < 126 {
            len as u8
        } else if len <= 65535 {
            126
        } else {
            127
        }
    );
}

fn write_truncated_length(
    out: &mut Vec<u8>,
    fin: bool,
    opcode: Opcode,
    mask: Option<[u8; 4]>,
    len: usize,
) {
    out.push((if fin { 128 } else { 0 }) | opcode.to_u8());
    out.push((if mask.is_some() { 128 } else { 0 }) | (len as u8 & 127));
    if let Some(key) = mask {
        out.extend_from_slice(&key);
    }
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(write_header, write_truncated_length)]
fn websocket_control_without_extended_length() {
    websocket_writer_uses_minimal_length();
}

fn add_mask(data: &mut [u8], key: [u8; 4], offset: usize) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = byte.wrapping_add(key[offset.wrapping_add(i) % 4]);
    }
}

fn restart_mask(data: &mut [u8], key: [u8; 4], _: usize) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % 4];
    }
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(apply_mask, add_mask)]
fn websocket_control_without_mask_involution() {
    mask_is_involution_and_composes([0; 8], [1, 2, 3, 4], 0, 1);
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(apply_mask, restart_mask)]
fn websocket_control_without_mask_offset() {
    mask_is_involution_and_composes([0; 8], [1, 2, 3, 4], 0, 1);
}

#[kani::proof]
#[kani::unwind(12)]
#[kani::stub(apply_mask, omit_mask)]
fn websocket_control_without_frame_masking() {
    small_frames_write::<4, true>([0; 4], true, [1, 2, 3, 4]);
}

fn close_payload(bytes: [u8; 6], n: usize) {
    kani::assume(n <= bytes.len());
    let result = parse_close(&bytes[..n]);
    if n == 0 {
        assert_eq!(result, Ok(None));
    } else if n == 1 {
        assert_eq!(result, Err(Error::CloseShort));
    } else {
        let code = u16::from_be_bytes([bytes[0], bytes[1]]);
        let allowed = (1000..=1003).contains(&code)
            || (1007..=1014).contains(&code)
            || (3000..=4999).contains(&code);
        let reason = core::str::from_utf8(&bytes[2..n]);
        assert_eq!(result.is_ok(), allowed && reason.is_ok());
        if let Ok(Some(close)) = result {
            assert_eq!(close.code, code);
            assert_eq!(close.reason.as_bytes(), &bytes[2..n]);
        }
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_close_payload_validates_reason() {
    close_payload(kani::any(), kani::any());
}

fn lossy_close(payload: &[u8]) -> Result<Close, Error> {
    let [hi, lo, rest @ ..] = payload else {
        return Err(Error::CloseShort);
    };
    let code = u16::from_be_bytes([*hi, *lo]);
    if !close_code::is_sendable(code) {
        return Err(Error::CloseCode(code));
    }
    Ok(Close {
        code,
        reason: String::from_utf8_lossy(rest).into_owned(),
    })
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(Close::parse, lossy_close)]
fn websocket_control_without_close_utf8() {
    close_payload([3, 232, 255, 0, 0, 0], 3);
}

fn write_wide_length(
    out: &mut Vec<u8>,
    fin: bool,
    opcode: Opcode,
    mask: Option<[u8; 4]>,
    len: usize,
) {
    out.push((if fin { 128 } else { 0 }) | opcode.to_u8());
    out.push((if mask.is_some() { 128 } else { 0 }) | 127);
    out.extend_from_slice(&(len as u64).to_be_bytes());
    if let Some(key) = mask {
        out.extend_from_slice(&key);
    }
}

#[kani::proof]
#[kani::unwind(16)]
#[kani::stub(write_header, write_wide_length)]
fn websocket_control_without_minimal_length() {
    websocket_writer_uses_minimal_length();
}

fn writer_follows_frame_rules<const N: usize>(
    opcode: Opcode,
    fin: bool,
    mask: Option<[u8; 4]>,
    data: [u8; N],
) {
    let op = opcode.to_u8();
    let payload = &data[..];
    let control = op >= 8;
    let close_ok = op != 8
        || match payload {
            [] => true,
            [hi, lo, reason @ ..] => {
                let code = u16::from_be_bytes([*hi, *lo]);
                ((1000..=1003).contains(&code)
                    || (1007..=1014).contains(&code)
                    || (3000..=4999).contains(&code))
                    && core::str::from_utf8(reason).is_ok()
            }
            [_] => false,
        };
    let mut out = Vec::new();
    let result = write_frame(&mut out, fin, opcode, mask, payload);
    // 5.5: control frames are final; 5.5.1: a Close body is a valid code
    // and a UTF-8 reason.
    assert!(result.is_ok() == (!(control && !fin) && close_ok));
    if result.is_err() {
        assert!(out.is_empty());
        return;
    }
    // 5.2: reserved bits clear, FIN and opcode as asked, mask bit set
    // exactly when a key is given.
    assert!(out[0] & 0x70 == 0);
    assert!((out[0] & 0x80 != 0) == fin);
    assert!(out[0] & 0x0f == op);
    assert!((out[1] & 0x80 != 0) == mask.is_some());
    let Ok(header) = Header::parse_exact(&out) else {
        panic!("a written frame reads back");
    };
    let Some(frame) = Frame::from_header(&out, header) else {
        panic!("a written frame reads back");
    };
    assert!(frame.fin == fin && frame.opcode == opcode && frame.mask == mask);
    assert!(frame.payload.as_slice() == payload);
}

// One harness per opcode and payload length, with any FIN, mask and
// payload bytes. Every opcode the writer can take (the type has no
// reserved ones) gets two bytes; Close gets 0 to 3 bytes, since three
// bytes hold a code and a one-byte reason.
macro_rules! writer_case {
    ($name:ident, $opcode:expr, $len:expr) => {
        #[kani::proof]
        #[kani::unwind(10)]
        fn $name() {
            writer_follows_frame_rules::<$len>($opcode, kani::any(), kani::any(), kani::any());
        }
    };
}
writer_case!(websocket_writer_rules_continuation, Opcode::Continuation, 2);
writer_case!(websocket_writer_rules_text, Opcode::Text, 2);
writer_case!(websocket_writer_rules_binary, Opcode::Binary, 2);
writer_case!(websocket_writer_rules_ping, Opcode::Ping, 2);
writer_case!(websocket_writer_rules_pong, Opcode::Pong, 2);
writer_case!(websocket_writer_rules_close_zero, Opcode::Close, 0);
writer_case!(websocket_writer_rules_close_one, Opcode::Close, 1);
writer_case!(websocket_writer_rules_close_two, Opcode::Close, 2);
writer_case!(websocket_writer_rules_close_three, Opcode::Close, 3);

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(Opcode::is_control, ignore_control_kind)]
fn websocket_control_without_writer_control_rules() {
    writer_follows_frame_rules(Opcode::Ping, false, None, [0; 0]);
}

fn write_reserved_bit(
    out: &mut Vec<u8>,
    fin: bool,
    opcode: Opcode,
    mask: Option<[u8; 4]>,
    len: usize,
) {
    out.push(if fin { 0x80 } else { 0 } | 0x40 | opcode.to_u8());
    out.push(if mask.is_some() { 0x80 } else { 0 } | len as u8);
    if let Some(key) = mask {
        out.extend_from_slice(&key);
    }
}

#[kani::proof]
#[kani::unwind(10)]
#[kani::stub(write_header, write_reserved_bit)]
fn websocket_control_without_writer_reserved_bits() {
    writer_follows_frame_rules(Opcode::Binary, true, None, [0; 0]);
}

fn writer_bounds_control_payload(opcode: Opcode, fin: bool, len: usize) {
    let mut payload = vec![b'a'; len];
    if opcode == Opcode::Close {
        payload[..2].copy_from_slice(&close_code::NORMAL.to_be_bytes());
    }
    let mut out = Vec::new();
    let result = write_frame(&mut out, fin, opcode, None, &payload);
    // 5.5: at most 125 bytes, and final.
    assert!(result.is_ok() == (fin && len <= MAX_CONTROL_PAYLOAD));
}

// One harness per control opcode, at 125 and 126 bytes, with any FIN.
macro_rules! control_size_case {
    ($name:ident, $opcode:expr) => {
        #[kani::proof]
        #[kani::unwind(130)]
        fn $name() {
            let len: usize = kani::any();
            kani::assume(len == 125 || len == 126);
            writer_bounds_control_payload($opcode, kani::any(), len);
        }
    };
}
control_size_case!(websocket_writer_bounds_control_payload_ping, Opcode::Ping);
control_size_case!(websocket_writer_bounds_control_payload_pong, Opcode::Pong);
control_size_case!(websocket_writer_bounds_control_payload_close, Opcode::Close);

#[kani::proof]
#[kani::unwind(130)]
#[kani::stub(Opcode::is_control, ignore_control_kind)]
fn websocket_control_without_writer_control_size() {
    writer_bounds_control_payload(Opcode::Ping, true, 126);
}

fn fragments_follow_rfc(message: Message, body: &[u8], max: usize, mask: Option<[u8; 4]>) {
    let Ok(frames) = message.to_frames(max, mask) else {
        panic!("small messages fit");
    };
    let size = max.clamp(1, MAX_PAYLOAD);
    if message.opcode().is_control() {
        // 5.5: a control message is one final frame.
        assert!(frames.len() == 1);
    }
    // 5.4: the first frame carries the opcode, the rest are continuations,
    // only the last is final, and the payloads in order are the message.
    // Each frame is one the writer accepts.
    let mut joined = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        let expected = if i == 0 {
            message.opcode()
        } else {
            Opcode::Continuation
        };
        assert!(f.opcode == expected);
        assert!(f.fin == (i + 1 == frames.len()));
        assert!(f.mask == mask);
        assert!(f.payload.len() <= size || message.opcode().is_control());
        assert!(!f.payload.is_empty() || frames.len() == 1);
        joined.extend_from_slice(&f.payload);
        assert!(f.to_bytes().is_ok());
    }
    assert!(joined.as_slice() == body);
}

// One harness per message kind, with any payload bytes and any fragment
// size up to 4 (0 is clamped to 1). Text and binary take 0 or 3 bytes,
// Ping and Pong 3. Unmasked: masking is proved by the mask and
// small-frame harnesses.
fn any_fragment_size() -> usize {
    let max: usize = kani::any();
    kani::assume(max <= 4);
    max
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_fragments_follow_rfc_text_empty() {
    fragments_follow_rfc(Message::Text(String::new()), &[], any_fragment_size(), None);
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_fragments_follow_rfc_text_three() {
    let data: [u8; 3] = kani::any();
    let Ok(text) = String::from_utf8(data.to_vec()) else {
        return;
    };
    fragments_follow_rfc(Message::Text(text), &data, any_fragment_size(), None);
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_fragments_follow_rfc_binary_empty() {
    fragments_follow_rfc(Message::Binary(Vec::new()), &[], any_fragment_size(), None);
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_fragments_follow_rfc_binary_three() {
    let data: [u8; 3] = kani::any();
    fragments_follow_rfc(
        Message::Binary(data.to_vec()),
        &data,
        any_fragment_size(),
        None,
    );
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_fragments_follow_rfc_ping() {
    let data: [u8; 3] = kani::any();
    fragments_follow_rfc(
        Message::Ping(data.to_vec()),
        &data,
        any_fragment_size(),
        None,
    );
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_fragments_follow_rfc_pong() {
    let data: [u8; 3] = kani::any();
    fragments_follow_rfc(
        Message::Pong(data.to_vec()),
        &data,
        any_fragment_size(),
        None,
    );
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_fragments_follow_rfc_close() {
    fragments_follow_rfc(Message::Close(None), &[], any_fragment_size(), None);
}

fn frames_all_final(
    message: &Message,
    max_fragment: usize,
    mask: Option<[u8; 4]>,
) -> Result<Vec<Frame>, Error> {
    let frame = message.to_frame(mask)?;
    let size = max_fragment.clamp(1, MAX_PAYLOAD);
    if frame.opcode.is_control() || frame.payload.len() <= size {
        return Ok(vec![frame]);
    }
    Ok(frame
        .payload
        .chunks(size)
        .enumerate()
        .map(|(i, chunk)| Frame {
            fin: true,
            opcode: if i == 0 {
                frame.opcode
            } else {
                Opcode::Continuation
            },
            mask,
            payload: chunk.to_vec(),
        })
        .collect())
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(Message::to_frames, frames_all_final)]
fn websocket_control_without_fragment_fin() {
    fragments_follow_rfc(Message::Binary(vec![1, 2]), &[1, 2], 1, None);
}

fn frames_split_control(
    message: &Message,
    max_fragment: usize,
    mask: Option<[u8; 4]>,
) -> Result<Vec<Frame>, Error> {
    let frame = message.to_frame(mask)?;
    let size = max_fragment.clamp(1, MAX_PAYLOAD);
    let count = frame.payload.len().div_ceil(size).max(1);
    Ok((0..count)
        .map(|i| Frame {
            fin: i + 1 == count,
            opcode: if i == 0 {
                frame.opcode
            } else {
                Opcode::Continuation
            },
            mask,
            payload: frame.payload[i * size..frame.payload.len().min((i + 1) * size)].to_vec(),
        })
        .collect())
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(Message::to_frames, frames_split_control)]
fn websocket_control_without_control_unsplit() {
    fragments_follow_rfc(Message::Ping(vec![1, 2]), &[1, 2], 1, None);
}
