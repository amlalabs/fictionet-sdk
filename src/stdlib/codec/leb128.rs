//! Unsigned LEB128 integers with caller-owned input and output, and zigzag transforms.

/// Reads an unsigned varint with byte and value bounds, preserving input errors.
///
/// Accepts encodings longer than necessary. Calls `next` at most
/// `max_bytes.min(10)` times and stops at the first byte without a continuation
/// bit. Returns `overflow` if the encoding exceeds either bound. Bytes already
/// read are not rolled back on error.
#[inline]
pub fn decode_with<E>(
    mut next: impl FnMut() -> Result<u8, E>,
    max_bytes: usize,
    max: u64,
    overflow: E,
) -> Result<u64, E> {
    let mut value = 0u64;
    for i in 0..max_bytes.min(10) {
        let byte = next()?;
        if i == 9 && byte > 1 {
            return Err(overflow);
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return if value <= max {
                Ok(value)
            } else {
                Err(overflow)
            };
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

/// Maps a signed 64-bit number onto an unsigned one, so that small
/// negative numbers make short varints: 0, -1, 1, -2 become 0, 1, 2, 3.
pub fn zigzag_encode64(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// Undoes [`zigzag_encode64`].
pub fn zigzag_decode64(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

/// Maps a signed 32-bit number onto an unsigned one, as `sint32` fields do.
pub fn zigzag_encode32(v: i32) -> u32 {
    ((v << 1) ^ (v >> 31)) as u32
}

/// Undoes [`zigzag_encode32`].
pub fn zigzag_decode32(v: u32) -> i32 {
    ((v >> 1) as i32) ^ -((v & 1) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;
    #[test]
    fn zigzag_vectors() {
        for (signed, unsigned) in [
            (0, 0),
            (-1, 1),
            (1, 2),
            (-2, 3),
            (i32::MAX, u32::MAX - 1),
            (i32::MIN, u32::MAX),
        ] {
            assert_eq!(zigzag_encode32(signed), unsigned);
            assert_eq!(zigzag_decode32(unsigned), signed);
            assert_eq!(zigzag_encode64(i64::from(signed)), u64::from(unsigned));
            assert_eq!(zigzag_decode64(u64::from(unsigned)), i64::from(signed));
        }
        for (signed, unsigned) in [(i64::MAX, u64::MAX - 1), (i64::MIN, u64::MAX)] {
            assert_eq!(zigzag_encode64(signed), unsigned);
            assert_eq!(zigzag_decode64(unsigned), signed);
        }
    }

    #[test]
    fn zigzag_width_roundtrips() {
        for bit in 0..32 {
            for unsigned in [(1u32 << bit) - 1, 1u32 << bit, u32::MAX >> bit] {
                assert_eq!(zigzag_encode32(zigzag_decode32(unsigned)), unsigned);
                let signed = unsigned as i32;
                assert_eq!(zigzag_decode32(zigzag_encode32(signed)), signed);
            }
        }
        for bit in 0..64 {
            for unsigned in [(1u64 << bit) - 1, 1u64 << bit, u64::MAX >> bit] {
                assert_eq!(zigzag_encode64(zigzag_decode64(unsigned)), unsigned);
                let signed = unsigned as i64;
                assert_eq!(zigzag_decode64(zigzag_encode64(signed)), signed);
            }
        }
    }

    #[test]
    fn bounds_and_roundtrips() {
        for n in [0, 127, 128, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            encode_with(n, |c| b.push(c));
            let mut it = b.into_iter();
            assert_eq!(
                decode_with(|| it.next().ok_or("short"), 10, u64::MAX, "overflow"),
                Ok(n)
            );
        }
        for b in [
            &[0x80; 11][..],
            &[0xff; 10],
            &[0x80, 0x80, 0x80, 0x80, 0x10],
        ] {
            let mut it = b.iter().copied();
            assert_eq!(
                decode_with(|| it.next().ok_or("short"), 5, u32::MAX as u64, "overflow"),
                Err("overflow")
            );
        }
        let mut it = [0x80].into_iter();
        assert_eq!(
            decode_with(|| it.next().ok_or("short"), 10, u64::MAX, "overflow"),
            Err("short")
        );
        let mut it = [0x80, 0].into_iter();
        assert_eq!(
            decode_with(|| it.next().ok_or("short"), 10, u64::MAX, "overflow"),
            Ok(0)
        );
    }
}
