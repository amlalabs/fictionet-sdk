//! Unsigned LEB128 and zigzag: encoding then decoding gives the value back
//! in the shortest form, decoding never panics and keeps both bounds, and
//! zigzag is a bijection on each width.

use super::bytes;
use fictionet::stdlib::codec::leb128::{
    decode_with, encode_with, zigzag_decode32, zigzag_decode64, zigzag_encode32, zigzag_encode64,
};

/// The shortest LEB128 length of `value`: one byte per seven bits, at least one.
fn shortest_len(value: u64) -> usize {
    (((64 - value.leading_zeros()) as usize).max(1)).div_ceil(7)
}

#[kani::proof]
#[kani::unwind(12)]
fn every_u64_roundtrips_in_its_shortest_form() {
    let value: u64 = kani::any();
    let mut out = [0u8; 10];
    let mut len = 0;
    encode_with(value, |byte| {
        out[len] = byte;
        len += 1;
    });
    assert_eq!(len, shortest_len(value));
    assert!(out[..len - 1].iter().all(|b| b & 0x80 != 0));
    assert_eq!(out[len - 1] & 0x80, 0);
    let mut at = 0;
    let decoded = decode_with(
        || {
            let byte = out.get(at).copied().ok_or(false);
            at += 1;
            byte
        },
        10,
        u64::MAX,
        true,
    );
    assert_eq!(decoded, Ok(value));
    assert_eq!(at, len);
}

#[kani::proof]
#[kani::unwind(12)]
fn decoding_keeps_both_bounds_on_every_input() {
    let (input, len) = bytes::<10>();
    let input = &input[..len];
    let max_bytes: usize = kani::any();
    let max: u64 = kani::any();
    let mut at = 0;
    let result = decode_with(
        || {
            let byte = input.get(at).copied().ok_or(false);
            at += 1;
            byte
        },
        max_bytes,
        max,
        true,
    );
    assert!(at <= max_bytes.min(10).max(1));
    match result {
        Ok(value) => {
            assert!(value <= max);
            assert!(at >= 1 && at <= len);
            assert_eq!(input[at - 1] & 0x80, 0);
            let mut again = 0u64;
            for (i, byte) in input[..at].iter().enumerate() {
                again |= u64::from(byte & 0x7f) << (7 * i);
            }
            assert_eq!(value, again);
        }
        Err(short) => {
            // `false` is the input error; `true` is the overflow error.
            if !short {
                assert!(at > len);
            }
        }
    }
}

#[kani::proof]
fn zigzag_is_a_bijection() {
    let signed32: i32 = kani::any();
    assert_eq!(zigzag_decode32(zigzag_encode32(signed32)), signed32);
    let unsigned32: u32 = kani::any();
    assert_eq!(zigzag_encode32(zigzag_decode32(unsigned32)), unsigned32);
    let signed64: i64 = kani::any();
    assert_eq!(zigzag_decode64(zigzag_encode64(signed64)), signed64);
    let unsigned64: u64 = kani::any();
    assert_eq!(zigzag_encode64(zigzag_decode64(unsigned64)), unsigned64);
    // Small magnitudes make small codes.
    assert!(u64::from(zigzag_encode32(signed32)) <= 2 * u64::from(signed32.unsigned_abs()));
    assert!(u128::from(zigzag_encode64(signed64)) <= 2 * u128::from(signed64.unsigned_abs()));
}
