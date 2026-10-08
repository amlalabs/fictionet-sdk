//! Unsigned LEB128 integers with caller-owned input and output.

/// Reads an unsigned varint with byte and value bounds, preserving input errors.
#[inline]
pub fn decode_with<E>(mut next: impl FnMut() -> Result<u8, E>, max_bytes: usize, max: u64, overflow: E) -> Result<u64, E> {
    let mut value = 0u64;
    for i in 0..max_bytes.min(10) {
        let byte = next()?;
        if i == 9 && byte > 1 { return Err(overflow); }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return if value <= max { Ok(value) } else { Err(overflow) };
        }
    }
    Err(overflow)
}

/// Emits an unsigned varint in its shortest form, one byte at a time.
#[inline]
pub fn encode_with(mut value: u64, mut emit: impl FnMut(u8)) {
    while value >= 0x80 {
        emit((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    emit(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;
    #[test]
    fn bounds_and_roundtrips() {
        for n in [0, 127, 128, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            encode_with(n, |c| b.push(c));
            let mut it = b.into_iter();
            assert_eq!(decode_with(|| it.next().ok_or("short"), 10, u64::MAX, "overflow"), Ok(n));
        }
        for b in [&[0x80; 11][..], &[0xff; 10], &[0x80, 0x80, 0x80, 0x80, 0x10]] {
            let mut it = b.iter().copied();
            assert_eq!(decode_with(|| it.next().ok_or("short"), 5, u32::MAX as u64, "overflow"), Err("overflow"));
        }
        let mut it = [0x80].into_iter();
        assert_eq!(decode_with(|| it.next().ok_or("short"), 10, u64::MAX, "overflow"), Err("short"));
        let mut it = [0x80, 0].into_iter();
        assert_eq!(decode_with(|| it.next().ok_or("short"), 10, u64::MAX, "overflow"), Ok(0));
    }
}
