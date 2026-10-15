//! IEEE CRC-32 checksums.
//!
//! This uses the IEEE polynomial. CRC-32C uses the Castagnoli polynomial
//! and is provided separately by [`crc32c`](fictionet::stdlib::codec::crc32c).

/// The CRC-32 of `data`: the IEEE 802.3 polynomial, reflected, starting
/// from all ones and inverted at the end.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = CRC_TABLE
            .get(usize::from((crc as u8) ^ byte))
            .copied()
            .unwrap_or_default()
            ^ (crc >> 8);
    }
    !crc
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
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
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
