//! Kani proofs over the RFC 7541 Huffman code in
//! src/stdlib/protocols/huffman.rs, which HPACK decodes every coded string
//! with (`ReadFields::string` in hpack.rs calls `decode_limited`). Compiled
//! only under `cargo kani`, as a child module of huffman.rs, so each harness
//! calls the production `encode`, `encoded_len` and `decode_limited`.
//!
//! The code table itself (`HUFFMAN_LENGTHS`, from which `build_huffman`
//! derives the canonical codes) was compared with RFC 7541 Appendix B once,
//! symbol by symbol; see verification/hpack-grpc/README.md.

use super::*;

/// The bits of `codes`, each `(code, length)` in order, followed by `pad`
/// bits of `padding` (its low bits), packed into whole bytes. The total
/// must be a multiple of eight.
fn pack(codes: &[(u32, u32)], pad: u32, padding: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u64, 0u32);
    let mut put = |code: u32, len: u32, acc: &mut u64, bits: &mut u32| {
        *acc = (*acc << len) | u64::from(code);
        *bits += len;
        while *bits >= 8 {
            *bits -= 8;
            out.push((*acc >> *bits) as u8);
        }
        *acc &= (1 << *bits) - 1;
    };
    for &(code, len) in codes {
        put(code, len, &mut acc, &mut bits);
    }
    put(padding & ((1 << pad) - 1), pad, &mut acc, &mut bits);
    assert_eq!(bits, 0);
    out
}

fn code(symbol: usize) -> (u32, u32) {
    (HUFFMAN.codes[symbol], u32::from(HUFFMAN_LENGTHS[symbol]))
}

/// Any input of up to four bytes that `decode_limited` accepts, with any
/// limit, is exactly the encoding of what it returns: the same bytes come
/// back from `encode`, and the result is within the limit. So the decoder
/// accepts nothing outside the code: no EOS, no padding but the at most
/// seven one bits `encode` writes, no code left unfinished. Four bytes hold
/// any one symbol, including the 30-bit ones and EOS.
#[kani::proof]
#[kani::unwind(10)]
fn decoding_accepts_only_encoded_strings() {
    let bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 4);
    let input = &bytes[..len];
    let limit: usize = kani::any();
    if let Ok(out) = decode_limited(input, limit) {
        assert!(out.len() <= limit);
        let mut back = Vec::new();
        assert_eq!(encode(&out, &mut back), Ok(()));
        assert_eq!(back.as_slice(), input);
    }
}

/// Any two octets encode to `encoded_len` bytes that decode back to the
/// same two octets, and are refused with `TooLong` under a limit of one.
/// With `decoding_accepts_only_encoded_strings`, the decoder accepts
/// exactly the strings `encode` writes.
#[kani::proof]
#[kani::unwind(10)]
fn encoded_strings_decode_back() {
    let s: [u8; 2] = kani::any();
    let mut out = Vec::new();
    assert_eq!(encode(&s, &mut out), Ok(()));
    assert_eq!(encoded_len(&s), Ok(out.len()));
    assert_eq!(decode_limited(&out, 2).as_deref(), Ok(&s[..]));
    assert_eq!(decode_limited(&out, 1), Err(Error::TooLong));
}

/// EOS after any symbol, padded with one bits to a byte, is refused, and
/// so is EOS alone.
#[kani::proof]
#[kani::unwind(10)]
fn eos_in_a_string_is_refused() {
    let symbol: u8 = kani::any();
    let first = code(usize::from(symbol));
    let eos = code(256);
    let pad = (8 - (first.1 + eos.1) % 8) % 8;
    let bytes = pack(&[first, eos], pad, u32::MAX);
    assert_eq!(decode_limited(&bytes, usize::MAX), Err(Error::InvalidCode));
    let pad = (8 - eos.1 % 8) % 8;
    let bytes = pack(&[eos], pad, u32::MAX);
    assert_eq!(decode_limited(&bytes, usize::MAX), Err(Error::InvalidCode));
}

/// After any symbol, padding to either of the next two byte boundaries
/// with any bits gives that symbol back exactly when the padding is at most
/// seven bits and all ones. Eight or more one bits, or any zero bit, never
/// give the symbol alone.
#[kani::proof]
#[kani::unwind(10)]
fn padding_is_at_most_seven_one_bits() {
    let symbol: u8 = kani::any();
    let first = code(usize::from(symbol));
    let short = (8 - first.1 % 8) % 8;
    let pad = if kani::any() { short } else { short + 8 };
    let padding: u32 = kani::any();
    let bytes = pack(&[first], pad, padding);
    let ones = (1u32 << pad) - 1;
    let good = pad <= 7 && padding & ones == ones;
    let decoded = decode_limited(&bytes, usize::MAX);
    assert_eq!(decoded.as_deref() == Ok(&[symbol][..]), good);
}
