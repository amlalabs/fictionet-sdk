//! The table-driven CRCs agree with the bit-at-a-time definition of each
//! polynomial, and CRC-32C's running state composes across any split.

use super::bytes;
use fictionet::stdlib::codec::{crc32, crc32c};

/// The reflected CRC-32 of `data` for `polynomial`, one bit at a time,
/// from all ones and inverted at the end: the definition the tables encode.
fn bitwise(polynomial: u32, data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ polynomial
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[kani::proof]
#[kani::unwind(10)]
fn crc32_matches_the_ieee_definition() {
    let (data, len) = bytes::<3>();
    assert_eq!(crc32(&data[..len]), bitwise(0xedb8_8320, &data[..len]));
}

#[kani::proof]
#[kani::unwind(10)]
fn crc32c_matches_the_castagnoli_definition_and_composes() {
    let (data, len) = bytes::<3>();
    let data = &data[..len];
    assert_eq!(crc32c::checksum(data), bitwise(0x82f6_3b78, data));
    let split: usize = kani::any();
    kani::assume(split <= len);
    assert_eq!(
        !crc32c::update(crc32c::update(!0, &data[..split]), &data[split..]),
        crc32c::checksum(data)
    );
}
