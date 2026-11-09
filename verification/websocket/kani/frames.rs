//! Bounded checks of the production WebSocket codec. Source mappings and
//! mutation controls are recorded in the adjacent README.
use super::*;
use crate::stdlib::codec::Decode;

#[kani::proof]
#[kani::unwind(16)]
fn websocket_headers_follow_wire_grammar() {
    let bytes: [u8; 14] = kani::any();
    let n: usize = kani::any();
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

#[kani::proof]
#[kani::unwind(8)]
fn websocket_small_frames_roundtrip() {
    let data: [u8; 4] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= data.len());
    let masked: bool = kani::any();
    let frame = Frame {
        fin: kani::any(),
        opcode: Opcode::Binary,
        mask: masked.then(|| kani::any()),
        payload: data[..n].to_vec(),
    };
    let wire = frame.to_bytes().unwrap();
    assert_eq!(wire[1] & 127, n as u8);
    assert_eq!(wire.len(), n + if masked { 6 } else { 2 });
    assert_eq!(Frame::parse(&wire).unwrap(), frame);
}

#[kani::proof]
#[kani::unwind(8)]
fn websocket_close_codes_follow_wire_ranges() {
    let code: u16 = kani::any();
    let allowed = (1000 <= code && code <= 1003)
        || (1007 <= code && code <= 1014)
        || (3000 <= code && code <= 4999);
    assert_eq!(Close::parse(&code.to_be_bytes()).is_ok(), allowed);
    assert_eq!(Close::new(code).to_bytes().is_ok(), allowed);
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

#[kani::proof]
#[kani::unwind(8)]
fn websocket_message_limit_precedes_payload_copy() {
    let held: usize = kani::any();
    let limit: usize = kani::any();
    let next: u8 = kani::any();
    kani::assume(held <= limit && limit <= 3 && next <= 125);
    let mut decoder = Messages::for_receiver(Side::Client).with_limit(limit);
    decoder.partial = Some(Partial {
        opcode: Opcode::Binary,
        data: vec![0; held],
        checked: 0,
    });
    let result = decoder.decode(&[0x80, next], false);
    if held + usize::from(next) > limit {
        assert!(matches!(
            result,
            Err(codec::AssembleError::Inner(Error::TooBig))
        ));
        assert_eq!(decoder.partial.as_ref().unwrap().data.len(), held);
    }
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
    websocket_headers_follow_wire_grammar();
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
#[kani::unwind(8)]
#[kani::stub(Frame::from_header, omit_payload_mask)]
fn websocket_control_without_unmasking() {
    websocket_small_frames_roundtrip();
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(close_code::is_sendable, allow_every_close)]
fn websocket_control_without_close_ranges() {
    websocket_close_codes_follow_wire_ranges();
}

#[kani::proof]
#[kani::unwind(8)]
#[kani::stub(Messages::held, omit_held)]
fn websocket_control_without_held_charge() {
    websocket_message_limit_precedes_payload_copy();
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
    let header = Header::parse(&bytes).unwrap().unwrap();
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
