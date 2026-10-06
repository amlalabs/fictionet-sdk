//! The RFC 7541 Huffman code shared by HPACK and QPACK.
//!
//! Use [`HuffmanString`] for a complete coded string, or [`encode`] and
//! [`decode`] for borrowed bytes. Length prefixes and the Huffman flag
//! belong to the enclosing header compression format.

use fictionet::stdlib::codec::Wire;

/// The largest decoded string, in bytes.
pub const MAX_STRING: usize = 64 << 10;
/// The largest encoded string, in bytes, at thirty bits per symbol.
pub const MAX_ENCODED: usize = MAX_STRING * 30 / 8;

/// Why Huffman coding failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid code, EOS in the string, or padding that is not at most seven one bits.
    InvalidCode,
    /// The encoded or decoded string exceeds its limit.
    TooLong,
    /// The value exceeds the writer's limit.
    Unwritable,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidCode => "invalid Huffman code or padding",
            Self::TooLong => "Huffman string exceeds its limit",
            Self::Unwritable => "Huffman string cannot be written",
        })
    }
}
impl core::error::Error for Error {}

/// Decoded octets whose wire form is an RFC 7541 Huffman string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HuffmanString(
    /// Decoded bytes, at most [`MAX_STRING`].
    pub Vec<u8>,
);

impl Wire for HuffmanString {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads a complete string. Refuses EOS, invalid padding, and size limits.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        decode(bytes).map(Self)
    }

    /// Appends the coded string. Refuses values above [`MAX_STRING`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        encode(&self.0, out)
    }
}

/// The length in bits of each symbol's Huffman code, 256 being the
/// end-of-string code. The code is canonical, so the lengths fix the codes.
#[rustfmt::skip]
const HUFFMAN_LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28,
    28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12,
    10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6,
    5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22,
    22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20,
    22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28,
    27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28,
    27, 27, 27, 27, 27, 26, 30,
];

/// The canonical code, worked out from the lengths at compile time.
struct Huffman {
    /// Each symbol's code, in its low bits.
    codes: [u32; 257],
    /// For each length: the first code of that length, how many codes
    /// have it, and where its symbols start in `symbols`.
    first: [u32; 31],
    count: [u32; 31],
    start: [u16; 31],
    /// The symbols, shortest code first.
    symbols: [u16; 257],
}

const HUFFMAN: Huffman = build_huffman();

const fn build_huffman() -> Huffman {
    let mut h = Huffman {
        codes: [0; 257],
        first: [0; 31],
        count: [0; 31],
        start: [0; 31],
        symbols: [0; 257],
    };
    let mut code = 0u32;
    let mut index = 0usize;
    let mut len = 1usize;
    while len <= 30 {
        h.first[len] = code;
        h.start[len] = index as u16;
        let mut s = 0usize;
        while s < 257 {
            if HUFFMAN_LENGTHS[s] as usize == len {
                h.codes[s] = code;
                h.symbols[index] = s as u16;
                h.count[len] += 1;
                index += 1;
                code += 1;
            }
            s += 1;
        }
        code <<= 1;
        len += 1;
    }
    h
}

/// The encoded byte count, including padding. Refuses input above [`MAX_STRING`].
pub fn encoded_len(s: &[u8]) -> Result<usize, Error> {
    if s.len() > MAX_STRING {
        return Err(Error::Unwritable);
    }
    let bits: usize = s
        .iter()
        .map(|&b| usize::from(HUFFMAN_LENGTHS[usize::from(b)]))
        .sum();
    Ok(bits.div_ceil(8))
}

/// Appends encoded bytes with EOS prefix padding. Refuses input above
/// [`MAX_STRING`] and leaves `out` unchanged on error.
pub fn encode(s: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    encoded_len(s)?;
    let (mut acc, mut bits) = (0u64, 0u32);
    for &b in s {
        let len = u32::from(HUFFMAN_LENGTHS[usize::from(b)]);
        acc = (acc << len) | u64::from(HUFFMAN.codes[usize::from(b)]);
        bits += len;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1 << pad) - 1)) as u8);
    }
    Ok(())
}

/// Decodes a Huffman-coded string. Padding must be fewer than 8 bits, all
/// 1s, and the end-of-string code may not appear. The result is at most
/// [`MAX_STRING`] bytes.
pub fn decode(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() > MAX_ENCODED {
        return Err(Error::TooLong);
    }
    let h = &HUFFMAN;
    let mut out = Vec::with_capacity((bytes.len().saturating_mul(8) / 5).min(MAX_STRING));
    let (mut code, mut len) = (0u32, 0usize);
    for byte in bytes {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if len > 30 {
                return Err(Error::InvalidCode);
            }
            if code >= h.first[len] && code - h.first[len] < h.count[len] {
                let sym = h.symbols[usize::from(h.start[len]) + (code - h.first[len]) as usize];
                if sym == 256 {
                    return Err(Error::InvalidCode);
                }
                if out.len() >= MAX_STRING {
                    return Err(Error::TooLong);
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            }
        }
    }
    if len < 8 && code == (1 << len) - 1 {
        Ok(out)
    } else {
        Err(Error::InvalidCode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::contract;
    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .flat_map(|s| s.as_bytes().chunks(2))
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    // RFC 7541 Appendix C.4: Huffman-coded strings.

    #[test]
    fn huffman_examples() {
        for (text, code) in [
            ("www.example.com", "f1e3 c2e5 f23a 6ba0 ab90 f4ff"),
            ("no-cache", "a8eb 1064 9cbf"),
            ("custom-key", "25a8 49e9 5ba9 7d7f"),
            ("custom-value", "25a8 49e9 5bb8 e8b4 bf"),
            ("302", "6402"),
            ("private", "aec3 771a 4b"),
            (
                "Mon, 21 Oct 2013 20:13:21 GMT",
                "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff",
            ),
            (
                "https://www.example.com",
                "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3",
            ),
        ] {
            assert_eq!(
                HuffmanString(text.as_bytes().to_vec()).to_bytes().unwrap(),
                hex(code),
                "{text}"
            );
            assert_eq!(
                HuffmanString::parse(&hex(code)).map(|s| s.0).unwrap(),
                text.as_bytes()
            );
            assert_eq!(encoded_len(text.as_bytes()).unwrap(), hex(code).len());
        }
    }

    #[test]
    fn huffman_every_byte_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(
            HuffmanString::parse(&HuffmanString(all.clone()).to_bytes().unwrap())
                .map(|s| s.0)
                .unwrap(),
            all
        );
        for b in 0..=255u8 {
            assert_eq!(
                HuffmanString::parse(&HuffmanString(vec![b]).to_bytes().unwrap())
                    .map(|s| s.0)
                    .unwrap(),
                [b]
            );
        }
        assert_eq!(HuffmanString::parse(&[]).map(|s| s.0).unwrap(), b"");
    }

    #[test]
    fn huffman_errors() {
        // Eight 1 bits of padding.
        assert_eq!(
            HuffmanString::parse(&[0xff]).map(|s| s.0),
            Err(Error::InvalidCode)
        );
        // The end-of-string code: thirty 1 bits.
        assert_eq!(
            HuffmanString::parse(&[0xff, 0xff, 0xff, 0xff]).map(|s| s.0),
            Err(Error::InvalidCode)
        );
        // 'a' (00011) padded with 0 bits.
        assert_eq!(
            HuffmanString::parse(&[0x18]).map(|s| s.0),
            Err(Error::InvalidCode)
        );
        assert_eq!(HuffmanString::parse(&[0x1f]).map(|s| s.0).unwrap(), b"a");
        // Too long once decoded: '0' is 5 bits, so this gives 1.6 bytes per byte.
        // Eight '0's are 40 zero bits, so MAX_STRING of them are MAX_STRING
        // * 5 / 8 zero bytes; five more bytes hold eight more.
        let long = vec![0; MAX_STRING * 5 / 8 + 5];
        assert_eq!(
            HuffmanString::parse(&long).map(|s| s.0),
            Err(Error::TooLong)
        );
        assert_eq!(
            HuffmanString::parse(&HuffmanString(vec![b'0'; MAX_STRING]).to_bytes().unwrap())
                .map(|s| s.0)
                .unwrap()
                .len(),
            MAX_STRING
        );
    }

    #[test]
    fn huffman_writer_refuses_truncation() {
        let long = HuffmanString(vec![b'0'; MAX_STRING + 1]);
        contract::check_wire_value(&long);
        assert_eq!(long.to_bytes(), Err(Error::Unwritable));
        contract::check_wire_value(&HuffmanString(vec![b'0'; MAX_STRING]));
    }
}
