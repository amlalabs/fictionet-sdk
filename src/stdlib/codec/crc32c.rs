//! CRC-32C (Castagnoli) checksums.

/// Computes the CRC-32C checksum of a byte slice.
#[inline]
pub fn checksum(bytes: &[u8]) -> u32 {
    !update(!0, bytes)
}

/// Updates an uncomplemented CRC-32C state, initialized to all ones and complemented at the end.
#[inline]
pub fn update(mut state: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        state = CRC32C_TABLE[((state ^ u32::from(b)) & 0xff) as usize] ^ (state >> 8);
    }
    state
}

const CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82f6_3b78 } else { c >> 1 };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_values_and_segments() {
        assert_eq!(checksum(b""), 0);
        assert_eq!(checksum(b"123456789"), 0xe306_9283);
        assert_eq!(checksum(&[0; 32]), 0x8a91_36aa);
        for i in 0..=9 { assert_eq!(!update(update(!0, &b"123456789"[..i]), &b"123456789"[i..]), 0xe306_9283); }
    }
}
