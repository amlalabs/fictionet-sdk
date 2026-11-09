//! Kani proofs over the framing of a passive HTTP/2 direction in
//! src/stdlib/dissect/http2.rs: `CaptureInputs::decode`, which finds the
//! preface and the frames, and `unpad`, which takes a DATA frame's padding
//! off. Compiled only under `cargo kani`, as a child module of http2.rs.

use super::*;

/// The longest input the framing harness gives the decoder: a frame
/// header and two bytes of payload.
const INPUT: usize = HEADER_LEN + 2;

/// For any bytes up to eleven long, before or after the preface, with any
/// payload left to skip, and at the end of the stream or not, one step
/// keeps the `Decode` contract and frames by the header:
///
/// - it never takes more than its input, and never takes nothing as a step;
/// - while skipping a payload too long to keep, it takes exactly what is
///   left of it in the input, and at the end of the stream with some left,
///   it fails rather than asking for more;
/// - while waiting for the preface, it asks for more only while the input
///   could still be the preface's start;
/// - otherwise an item is one frame: its header and exactly the length it
///   names, or, when that length is more than the buffer keeps and not all
///   there, the header alone, with the length left to skip.
#[kani::proof]
#[kani::unwind(13)]
fn frames_take_exactly_what_their_header_names() {
    let bytes: [u8; INPUT] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= INPUT);
    let input = &bytes[..len];
    let (preface, skip): (bool, usize) = (kani::any(), kani::any());
    let eof: bool = kani::any();
    let mut frames = CaptureInputs { preface, skip };
    let length = (len >= HEADER_LEN).then(|| {
        (usize::from(input[0]) << 16) | (usize::from(input[1]) << 8) | usize::from(input[2])
    });
    match frames.decode(input, eof) {
        Ok(Step::Skip(n)) => {
            assert!(skip != 0 && n > 0 && n <= len);
            assert_eq!(n, skip.min(len));
            assert_eq!(frames.skip, skip - n);
        }
        Ok(Step::Need) => {
            assert_eq!((frames.preface, frames.skip), (preface, skip));
            if skip != 0 {
                assert!(len == 0 && !eof);
            } else if preface && PREFACE.starts_with(input) {
                // The preface is 24 bytes: any shorter start of it waits.
            } else if let Some(length) = length {
                assert!(length <= CAPTURE_FRAME_LIMIT && len < HEADER_LEN + length);
            }
        }
        Ok(Step::Item(item, n)) => {
            assert_eq!(skip, 0);
            assert!(n <= len);
            assert!(!frames.preface);
            let length = length.unwrap();
            match item {
                CaptureInput::Preface => panic!("the preface is longer than the input"),
                CaptureInput::Refused {
                    oversized: true, ..
                } => {
                    assert!(length > CAPTURE_FRAME_LIMIT && len < HEADER_LEN + length);
                    assert_eq!(n, HEADER_LEN);
                    assert_eq!(frames.skip, length);
                }
                _ => {
                    assert_eq!(n, HEADER_LEN + length);
                    assert_eq!(frames.skip, 0);
                }
            }
        }
        Ok(Step::End) => panic!("the frames do not end themselves"),
        Err(_) => assert!(skip != 0 && len == 0 && eof || len >= HEADER_LEN),
    }
}

/// For any DATA payload up to four bytes and any flags, `unpad` gives
/// the payload itself without PADDED, and with it the bytes after the pad
/// length, short of exactly that many pad bytes, or nothing when the pad
/// is longer than the rest.
#[kani::proof]
#[kani::unwind(6)]
fn padding_comes_off_exactly() {
    let bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 4);
    let payload = &bytes[..len];
    let flags: u8 = kani::any();
    let data = unpad(payload, flags);
    if flags & 8 == 0 {
        assert!(data == Some(payload));
    } else if len == 0 || usize::from(payload[0]) > len - 1 {
        assert!(data.is_none());
    } else {
        let data = data.unwrap();
        assert_eq!(data.as_ptr() as usize, payload.as_ptr() as usize + 1);
        assert_eq!(data.len(), len - 1 - usize::from(payload[0]));
    }
}
