//! Standard base64 with protocol-specific padding rules.

extern crate alloc;

use alloc::{string::String, vec::Vec};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Returns the value of a standard base64 digit.
#[inline]
pub fn digit(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The padding and unused-bit rules for a base64 value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    /// Padding may be omitted; unused bits are ignored.
    Optional,
    /// Padding is required; unused bits are ignored.
    Required,
    /// Padding is required and unused bits must be zero.
    Canonical,
}

/// Emits standard base64 with padding, one ASCII byte at a time.
#[inline]
pub fn encode_with(data: &[u8], mut emit: impl FnMut(u8)) {
    for chunk in data.chunks(3) {
        let n = u32::from(chunk[0]) << 16
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for i in 0..4 {
            emit(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] } else { b'=' });
        }
    }
}

/// Encodes bytes as standard base64 with padding.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    encode_with(data, |c| out.push(char::from(c)));
    out
}

/// Checks base64 without allocating, using the given padding policy.
pub fn is_valid(text: &[u8], padding: Padding) -> bool {
    let body = text.strip_suffix(b"==").or_else(|| text.strip_suffix(b"=")).unwrap_or(text);
    if body.len() % 4 == 1
        || ((body.len() != text.len() || padding != Padding::Optional) && !text.len().is_multiple_of(4))
        || !body.iter().all(|&c| digit(c).is_some()) {
        return false;
    }
    if padding == Padding::Canonical {
        let mask = match body.len() % 4 { 2 => 15, 3 => 3, _ => 0 };
        if body.last().is_some_and(|&c| digit(c).unwrap_or(0) & mask != 0) { return false; }
    }
    true
}

/// Decodes base64 using the given padding policy, refusing whitespace and invalid digits.
pub fn decode(text: &[u8], padding: Padding) -> Option<Vec<u8>> {
    let bytes = decoded(text, padding)?;
    let mut out = Vec::with_capacity(text.len() / 4 * 3 + 2);
    out.extend(bytes);
    Some(out)
}

/// Returns a checked, allocation-free iterator over decoded base64 bytes.
#[inline]
pub fn decoded(text: &[u8], padding: Padding) -> Option<impl Iterator<Item = u8> + '_> {
    if !is_valid(text, padding) { return None; }
    let (mut bits, mut nbits) = (0u32, 0u32);
    Some(text.iter().filter_map(move |&c| {
        bits = ((bits << 6) | u32::from(digit(c)?)) & 0xfff;
        nbits += 6;
        if nbits < 8 { return None; }
        nbits -= 8;
        Some((bits >> nbits) as u8)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors_and_policies() {
        for (plain, code) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v")] {
            assert_eq!(encode(plain.as_bytes()), code);
            for p in [Padding::Optional, Padding::Required, Padding::Canonical] {
                assert_eq!(decode(code.as_bytes(), p).as_deref(), Some(plain.as_bytes()));
            }
        }
        assert_eq!(decode(b"Zg", Padding::Optional), Some(b"f".to_vec()));
        assert_eq!(decode(b"Zg", Padding::Required), None);
        assert_eq!(decode(b"Zh==", Padding::Required), Some(b"f".to_vec()));
        assert_eq!(decode(b"Zh==", Padding::Canonical), None);
        assert_eq!(decode(b"Zm9=", Padding::Canonical), None);
        for s in [b"=".as_slice(), b"==", b"====", b"Z", b"Zg=", b"Zg===", b"Zg==Zg==", b" Zg==", b"Z_=="] {
            for p in [Padding::Optional, Padding::Required, Padding::Canonical] {
                assert_eq!(decode(s, p), None);
            }
        }
        for c in 0..=255u8 {
            assert_eq!(digit(c), ALPHABET.iter().position(|&b| b == c).map(|n| n as u8));
        }
        assert_eq!(encode(&[0xfb, 0xff]), "+/8=");
    }
}
