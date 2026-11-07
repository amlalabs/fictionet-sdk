//! Base64: encoding then decoding gives the bytes back under every padding
//! policy; a text the canonical policy accepts re-encodes to itself; the
//! policies nest; and validation never panics on any text.

use super::bytes;
use fictionet::stdlib::codec::base64::{Padding, decoded, digit, encode_with, is_valid};

const POLICIES: [Padding; 3] = [Padding::Optional, Padding::Required, Padding::Canonical];

fn encode_into(data: &[u8], out: &mut [u8; 8]) -> usize {
    let mut n = 0;
    encode_with(data, |c| {
        out[n] = c;
        n += 1;
    });
    n
}

/// Decodes into a fixed array, returning the byte count.
fn decode_into(text: &[u8], padding: Padding, out: &mut [u8; 6]) -> Option<usize> {
    let mut n = 0;
    for byte in decoded(text, padding)? {
        out[n] = byte;
        n += 1;
    }
    Some(n)
}

#[kani::proof]
#[kani::unwind(10)]
fn every_input_roundtrips_under_every_policy() {
    let (data, len) = bytes::<5>();
    let data = &data[..len];
    let mut text = [0u8; 8];
    let n = encode_into(data, &mut text);
    assert_eq!(n, len.div_ceil(3) * 4);
    let text = &text[..n];
    let pads = text.iter().filter(|&&c| c == b'=').count();
    assert_eq!(pads, (3 - len % 3) % 3);
    assert!(text[..n - pads].iter().all(|&c| digit(c).is_some()));
    for padding in POLICIES {
        assert!(is_valid(text, padding));
        let mut back = [0u8; 6];
        let m = decode_into(text, padding, &mut back).unwrap();
        assert_eq!(&back[..m], data);
    }
}

#[kani::proof]
#[kani::unwind(10)]
fn canonical_text_reencodes_to_itself() {
    let (text, len) = bytes::<8>();
    let text = &text[..len];
    let mut plain = [0u8; 6];
    let Some(n) = decode_into(text, Padding::Canonical, &mut plain) else {
        return;
    };
    let digits = text.iter().filter(|&&c| digit(c).is_some()).count();
    assert_eq!(n, digits * 6 / 8);
    let mut again = [0u8; 8];
    let m = encode_into(&plain[..n], &mut again);
    assert_eq!(&again[..m], text);
}

#[kani::proof]
#[kani::unwind(10)]
fn the_policies_nest_and_validation_is_total() {
    let (text, len) = bytes::<8>();
    let text = &text[..len];
    let canonical = is_valid(text, Padding::Canonical);
    let required = is_valid(text, Padding::Required);
    let optional = is_valid(text, Padding::Optional);
    assert!(!canonical || required);
    assert!(!required || optional);
    // Padding is never accepted where the digits already fill the last quantum.
    let digits = text.iter().filter(|&&c| digit(c).is_some()).count();
    if optional {
        assert!(digits % 4 != 1);
        assert_eq!(
            len - digits,
            if len % 4 == 0 {
                (4 - digits % 4) % 4
            } else {
                0
            }
        );
    }
    if required {
        assert_eq!(len % 4, 0);
    }
}
