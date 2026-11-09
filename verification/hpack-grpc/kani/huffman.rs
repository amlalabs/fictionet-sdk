//! Kani proofs over the RFC 7541 Huffman code in
//! src/stdlib/protocols/huffman.rs, which HPACK decodes every coded string
//! with (`ReadFields::string` in hpack.rs calls `decode_limited`). Compiled
//! only under `cargo kani`, as a child module of huffman.rs, so each harness
//! calls the production `symbol`, `encode`, `encoded_len` and
//! `decode_limited`.
//!
//! The code table itself (`HUFFMAN_LENGTHS`, from which `build_huffman`
//! derives the canonical codes) is checked against RFC 7541 Appendix B in
//! verification/hpack-grpc/README.md. Inputs past two bytes make the
//! decoder's formulas too large for CBMC; EOS and padding after every one
//! of the 256 symbols, which take up to six bytes, are the exhaustive tests
//! `eos_after_every_symbol_is_refused` and
//! `padding_after_every_symbol_is_at_most_seven_one_bits` in huffman.rs.

use super::*;

fn code(symbol: usize) -> (u32, u32) {
    (HUFFMAN.codes[symbol], u32::from(HUFFMAN_LENGTHS[symbol]))
}

/// Any input of `N` bytes that `decode_limited` accepts, under a limit
/// larger than any `N` bytes decode to, is exactly the codes of the octets
/// it returns, in order, then fewer than eight one bits. So the decoder
/// accepts nothing outside the code: no EOS, no longer padding, no padding
/// with a zero bit, no code left unfinished. The codes come from the table
/// (`HUFFMAN.codes`), not from `encode`.
fn accepts_only_encoded_strings<const N: usize>() {
    let input: [u8; N] = kani::any();
    if let Ok(out) = decode_limited(&input, 8) {
        let (mut value, mut bits) = (0u64, 0u32);
        for &octet in &out {
            let (code, len) = code(usize::from(octet));
            value = (value << len) | u64::from(code);
            bits += len;
        }
        let total = 8 * N as u32;
        assert!(bits <= total && total - bits <= 7);
        let pad = total - bits;
        let wire = input.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        assert_eq!(wire, (value << pad) | ((1 << pad) - 1));
    }
}

/// `accepts_only_encoded_strings` for one byte. (The empty input decodes
/// to the empty string: `huffman_every_byte_round_trips` in huffman.rs.)
#[kani::proof]
#[kani::unwind(10)]
fn decoding_accepts_only_encoded_strings_1() {
    accepts_only_encoded_strings::<1>();
}

/// `accepts_only_encoded_strings` for two bytes, which hold every symbol
/// of up to 16 bits.
#[kani::proof]
#[kani::unwind(10)]
fn decoding_accepts_only_encoded_strings_2() {
    accepts_only_encoded_strings::<2>();
}

/// The lookup `decode_limited` makes at every bit is exactly the code
/// table: each of the 257 symbols, EOS included, is found from its own
/// code and length, and any code of 1 to 30 bits that is found is the code
/// of the symbol found. So the decoder ends a symbol exactly at the end of
/// a code, of any length, the 30-bit ones too, and no run of fewer than 30
/// one bits is a code (only EOS, thirty one bits, is all ones), which the
/// padding rule relies on. `HUFFMAN.codes` is checked against RFC 7541
/// Appendix B in verification/hpack-grpc/README.md.
#[kani::proof]
#[kani::unwind(260)]
fn the_lookup_is_exactly_the_code_table() {
    for s in 0..257 {
        assert_eq!(
            symbol(HUFFMAN.codes[s], usize::from(HUFFMAN_LENGTHS[s])),
            Some(s as u16)
        );
    }
    let len: usize = kani::any();
    kani::assume((1..=30).contains(&len));
    let code: u32 = kani::any();
    kani::assume(code < 1 << len);
    if let Some(s) = symbol(code, len) {
        let s = usize::from(s);
        assert!(s < 257);
        assert_eq!(HUFFMAN.codes[s], code);
        assert_eq!(usize::from(HUFFMAN_LENGTHS[s]), len);
    }
    if len < 30 {
        assert_eq!(symbol((1 << len) - 1, len), None);
    }
}
/// For any two bytes and any limit up to four (two bytes decode to at most
/// three octets), what `decode_limited` returns is within the limit.
#[kani::proof]
#[kani::unwind(10)]
fn decoding_keeps_to_the_limit() {
    let input: [u8; 2] = kani::any();
    let limit: usize = kani::any();
    kani::assume(limit <= 4);
    if let Ok(out) = decode_limited(&input, limit) {
        assert!(out.len() <= limit);
    }
}

/// Any two octets encode, after what `out` held, to exactly their codes
/// from the table, in order, then the fewest one bits (at most seven) that
/// fill the last byte, in `encoded_len` bytes. With
/// `the_lookup_is_exactly_the_code_table`, the decoder reads each of those
/// codes back as its octet; `huffman_every_byte_round_trips` in huffman.rs
/// decodes every encoded octet.
#[kani::proof]
#[kani::unwind(10)]
fn encoding_is_the_codes_then_ones() {
    let s: [u8; 2] = kani::any();
    let before: u8 = kani::any();
    let mut out = Vec::with_capacity(9);
    out.push(before);
    assert_eq!(encode(&s, &mut out), Ok(()));
    assert_eq!(out[0], before);
    let wire = &out[1..];
    assert_eq!(encoded_len(&s), Ok(wire.len()));
    let (first, second) = (code(usize::from(s[0])), code(usize::from(s[1])));
    let bits = first.1 + second.1;
    assert_eq!(wire.len() as u32, bits.div_ceil(8));
    let pad = 8 * wire.len() as u32 - bits;
    let value = (u64::from(first.0) << second.1) | u64::from(second.0);
    let got = wire.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    assert_eq!(got, (value << pad) | ((1 << pad) - 1));
}
