//! Kani proofs over the RFC 7541 section 5.1 prefix integers in
//! src/stdlib/protocols/prefix_int.rs, which HPACK reads every index, length
//! and size update with (`ReadFields::integer` in hpack.rs). Compiled only
//! under `cargo kani`, as a child module of prefix_int.rs, so each harness
//! calls the production `read` and `write`.

use super::*;

/// How the RFC reads `bytes`: the value worked out in `u128`, so nothing
/// wraps, with the byte count; or why it cannot be read. An integer fails
/// as `Overflow` at the first byte that takes the running value past
/// `u64::MAX`, and when it would need more than `MAX_BYTES` bytes. The
/// HPACK harnesses read integers through it in place of `read`, which
/// `read_is_the_rfc_integer` proves it equal to.
pub(crate) fn rfc(bytes: &[u8], prefix: u8) -> Result<(u64, usize), Error> {
    let mask = (1u128 << prefix) - 1;
    let first = u128::from(*bytes.first().ok_or(Error::Truncated)?) & mask;
    if first < mask {
        return Ok((first as u64, 1));
    }
    let mut value = mask;
    let mut i = 1;
    loop {
        if i >= MAX_BYTES {
            return Err(Error::Overflow);
        }
        let byte = *bytes.get(i).ok_or(Error::Truncated)?;
        value += u128::from(byte & 0x7f) << (7 * (i - 1));
        if value > u128::from(u64::MAX) {
            return Err(Error::Overflow);
        }
        if byte & 0x80 == 0 {
            return Ok((value as u64, i + 1));
        }
        i += 1;
    }
}

/// For any prefix width from 1 to 8 and any input of up to `MAX_BYTES`
/// bytes, `read` gives exactly what the RFC gives: the same value and
/// byte count, `Truncated` when the input ends inside the integer, and
/// `Overflow` for a value past `u64::MAX` or an encoding longer than
/// `MAX_BYTES`. Kani's overflow checks are on, so no step of `read` wraps.
/// Widths outside 1 to 8 are refused.
#[kani::proof]
#[kani::unwind(13)]
fn read_is_the_rfc_integer() {
    let bytes: [u8; MAX_BYTES] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= MAX_BYTES);
    let input = &bytes[..len];
    let prefix: u8 = kani::any();
    if !(1..=8).contains(&prefix) {
        assert_eq!(read(input, prefix), Err(Error::Prefix));
        return;
    }
    assert_eq!(read(input, prefix), rfc(input, prefix));
    // The flag bits above the prefix never change the value.
    if len > 0 {
        let mut flipped = bytes;
        flipped[0] ^= !(((1u16 << prefix) - 1) as u8);
        assert_eq!(read(&flipped[..len], prefix), read(input, prefix));
    }
}

/// Any `u64` written with any width and any flags outside the prefix reads
/// back as itself, taking every written byte, in at most `MAX_BYTES`
/// bytes, with the flags kept and the shortest encoding (no zero
/// continuation byte at the end). Flags inside the prefix, or a bad width,
/// are refused and leave `out` as it was.
#[kani::proof]
#[kani::unwind(13)]
fn write_reads_back_in_the_shortest_form() {
    let value: u64 = kani::any();
    let prefix: u8 = kani::any();
    let flags: u8 = kani::any();
    let before: u8 = kani::any();
    let mut out = vec![before];
    let result = write(&mut out, prefix, flags, value);
    if !(1..=8).contains(&prefix) {
        assert_eq!(result, Err(Error::Prefix));
        assert_eq!(out, [before]);
        return;
    }
    let mask = ((1u16 << prefix) - 1) as u8;
    if flags & mask != 0 {
        assert_eq!(result, Err(Error::Flags));
        assert_eq!(out, [before]);
        return;
    }
    assert_eq!(result, Ok(()));
    let written = &out[1..];
    assert!(written.len() <= MAX_BYTES);
    assert_eq!(read(written, prefix), Ok((value, written.len())));
    assert_eq!(written[0] & !mask, flags);
    if written.len() > 2 {
        assert_ne!(written[written.len() - 1], 0);
    }
}
