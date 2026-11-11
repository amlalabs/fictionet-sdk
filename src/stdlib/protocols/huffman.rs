//! The RFC 7541 Huffman code shared by HPACK and QPACK.
//!
//! Use [`HuffmanString`] for a complete coded string, or [`encode`] and
//! [`decode`] for borrowed bytes. Length prefixes and the Huffman flag
//! belong to the enclosing header compression format.

use fictionet::stdlib::codec::Wire;

/// The decoded string limit for [`decode`], [`encode`], and [`HuffmanString`].
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
static HUFFMAN_LENGTHS: [u8; 257] = [
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

static HUFFMAN: Huffman = build_huffman();

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
pub fn encode(s: &[u8], out: &mut impl Extend<u8>) -> Result<(), Error> {
    if s.len() > MAX_STRING {
        return Err(Error::Unwritable);
    }
    let (mut acc, mut bits) = (0u64, 0u32);
    for &b in s {
        let len = u32::from(HUFFMAN_LENGTHS[usize::from(b)]);
        acc = (acc << len) | u64::from(HUFFMAN.codes[usize::from(b)]);
        bits += len;
        while bits >= 8 {
            bits -= 8;
            out.extend([(acc >> bits) as u8]);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        let pad = 8 - bits;
        out.extend([((acc << pad) | ((1 << pad) - 1)) as u8]);
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
    decode_limited(bytes, MAX_STRING)
}

/// The symbol whose code is the low `len` bits of `code`, from one to 30
/// bits, if one has that code.
fn symbol(code: u32, len: usize) -> Option<u16> {
    let h = &HUFFMAN;
    let offset = code.checked_sub(h.first[len])?;
    (offset < h.count[len]).then(|| h.symbols[usize::from(h.start[len]) + offset as usize])
}

/// Decodes a Huffman string with at most `limit` decoded octets.
/// Refuses invalid codes, EOS, padding, and output above the limit.
/// The caller bounds the encoded input. Allocation is bounded by the smaller
/// of `limit` and the input length times eight fifths.
///
/// ```
/// use fictionet::stdlib::protocols::huffman::decode_limited;
/// assert_eq!(decode_limited(&[0x1f], 1)?, b"a");
/// # Ok::<(), fictionet::stdlib::protocols::huffman::Error>(())
/// ```
pub fn decode_limited(bytes: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(most_decoded(bytes.len()).min(limit));
    walk(bytes, |octet| {
        if out.len() >= limit {
            return Err(Error::TooLong);
        }
        out.push(octet);
        Ok(())
    })?;
    Ok(out)
}

/// Decodes a Huffman string into the start of `out`, writing nothing
/// past it, and returns how many octets it wrote. Refuses invalid codes,
/// EOS and padding as [`decode_limited`] does, and output longer than
/// `out` as [`Error::TooLong`]. Allocates nothing. The code may lie in
/// pieces: `bytes` yields its octets in order.
pub fn decode_into<'a>(
    bytes: impl IntoIterator<Item = &'a u8>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let mut written = 0;
    walk(bytes, |octet| {
        let slot = out.get_mut(written).ok_or(Error::TooLong)?;
        *slot = octet;
        written += 1;
        Ok(())
    })?;
    Ok(written)
}

/// How many octets a Huffman string decodes to, checking it as
/// [`decode_limited`] does, with at most `limit` of them. Allocates
/// nothing. The code may lie in pieces, as for [`decode_into`].
pub fn decoded_len<'a>(
    bytes: impl IntoIterator<Item = &'a u8>,
    limit: usize,
) -> Result<usize, Error> {
    let mut len = 0usize;
    walk(bytes, |_| {
        if len >= limit {
            return Err(Error::TooLong);
        }
        len += 1;
        Ok(())
    })?;
    Ok(len)
}

/// The most octets `len` encoded bytes decode to: the shortest code is
/// five bits.
pub fn most_decoded(len: usize) -> usize {
    len.saturating_mul(8) / 5
}

/// Reads the codes of `bytes` in order, handing each decoded octet to
/// `emit`, and checks the padding at the end. The one decoder every
/// entry point above shares.
fn walk<'a>(
    bytes: impl IntoIterator<Item = &'a u8>,
    mut emit: impl FnMut(u8) -> Result<(), Error>,
) -> Result<(), Error> {
    let (mut code, mut len) = (0u32, 0usize);
    for byte in bytes {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            if len > 30 {
                return Err(Error::InvalidCode);
            }
            if let Some(sym) = symbol(code, len) {
                if sym == 256 {
                    return Err(Error::InvalidCode);
                }
                emit(sym as u8)?;
                code = 0;
                len = 0;
            }
        }
    }
    if len < 8 && code == (1 << len) - 1 {
        Ok(())
    } else {
        Err(Error::InvalidCode)
    }
}

/// Bounded proofs that the decoder accepts exactly the code, run with `cargo kani`.
#[cfg(kani)]
#[path = "../../../verification/hpack-grpc/kani/huffman.rs"]
mod proofs;

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::test_support::assert_write;
    use fictionet::stdlib::test_support::hex;
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
    fn decoding_uses_the_callers_limit() {
        let bytes = vec![0; 60_000];
        assert_eq!(decode_limited(&bytes, 96_000).unwrap(), vec![b'0'; 96_000]);
        assert_eq!(decode_limited(&bytes, 95_999), Err(Error::TooLong));
        assert_eq!(decode(&bytes), Err(Error::TooLong));
        assert_eq!(decode_limited(&[], 0).unwrap(), b"");
        assert_eq!(decode_limited(&[0x1f], 0), Err(Error::TooLong));
        assert_eq!(decode_limited(&[0xff], 1), Err(Error::InvalidCode));
        assert_eq!(decode_limited(&[0x1f], usize::MAX).unwrap(), b"a");
    }

    /// Decoding into a slice or only counting agrees with decoding into a
    /// vector on every input: the same octets, the same length, the same
    /// refusals, and a slice one octet short is refused as too long.
    #[test]
    fn every_decoder_agrees_with_the_vector_decoder() {
        use fictionet::{Entropy, Seed, SeededEntropy};
        let entropy = SeededEntropy::new(Seed::from_u64(7));
        for round in 0..2000 {
            let len = (entropy.random_u64() % 24) as usize;
            let bytes: Vec<u8> = if round % 2 == 0 {
                // Valid strings, from random text.
                let text: Vec<u8> = (0..len).map(|_| entropy.random_u64() as u8).collect();
                HuffmanString(text).to_bytes().unwrap()
            } else {
                (0..len).map(|_| entropy.random_u64() as u8).collect()
            };
            let limit = most_decoded(bytes.len());
            let want = decode_limited(&bytes, limit);
            let mut out = vec![0xaa; limit];
            let got = decode_into(&bytes, &mut out).map(|n| out[..n].to_vec());
            assert_eq!(got, want, "{bytes:02x?}");
            assert_eq!(
                decoded_len(&bytes, limit),
                want.as_ref().map(Vec::len).map_err(|e| *e)
            );
            if let Ok(want) = &want
                && let Some(short) = want.len().checked_sub(1)
            {
                let mut out = vec![0; short];
                assert_eq!(decode_into(&bytes, &mut out), Err(Error::TooLong));
                assert_eq!(decoded_len(&bytes, short), Err(Error::TooLong));
            }
        }
    }

    /// The bits of `codes`, each `(code, length)`, then `pad` bits of
    /// `padding` (its low bits), as whole bytes. The total must fill them.
    fn pack(codes: &[(u32, u32)], pad: u32, padding: u32) -> Vec<u8> {
        let (mut out, mut acc, mut bits) = (Vec::new(), 0u64, 0u32);
        for &(code, len) in codes
            .iter()
            .chain([(padding & ((1 << pad) - 1), pad)].iter())
        {
            acc = (acc << len) | u64::from(code);
            bits += len;
            while bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
            acc &= (1 << bits) - 1;
        }
        assert_eq!(bits, 0);
        out
    }

    fn code(symbol: usize) -> (u32, u32) {
        (HUFFMAN.codes[symbol], u32::from(HUFFMAN_LENGTHS[symbol]))
    }

    // Every symbol in turn: these inputs take up to six bytes, past what the
    // Kani harnesses in verification/hpack-grpc/kani/huffman.rs reach.

    #[test]
    fn eos_after_every_symbol_is_refused() {
        let eos = code(256);
        for symbol in 0..256 {
            let first = code(symbol);
            let pad = (8 - (first.1 + eos.1) % 8) % 8;
            let bytes = pack(&[first, eos], pad, u32::MAX);
            assert_eq!(decode(&bytes), Err(Error::InvalidCode), "{symbol}");
            let pad = (8 - (2 * first.1 + eos.1) % 8) % 8;
            let bytes = pack(&[first, eos, first], pad, u32::MAX);
            assert_eq!(decode(&bytes), Err(Error::InvalidCode), "{symbol}");
        }
    }

    #[test]
    fn padding_after_every_symbol_is_at_most_seven_one_bits() {
        for symbol in 0..=255u8 {
            let first = code(usize::from(symbol));
            let short = (8 - first.1 % 8) % 8;
            // Padding to either of the next two byte boundaries, with every
            // value its bits can take.
            for pad in [short, short + 8] {
                let ones = (1u32 << pad) - 1;
                for padding in 0..=ones {
                    let decoded = decode(&pack(&[first], pad, padding));
                    let alone = decoded.as_deref() == Ok(&[symbol][..]);
                    assert_eq!(
                        alone,
                        pad <= 7 && padding == ones,
                        "{symbol} {pad} {padding}"
                    );
                }
            }
        }
    }

    #[test]
    fn huffman_writer_refuses_truncation() {
        let long = HuffmanString(vec![b'0'; MAX_STRING + 1]);
        let _ = assert_write(&long);
        assert_eq!(long.to_bytes(), Err(Error::Unwritable));
        let _ = assert_write(&HuffmanString(vec![b'0'; MAX_STRING]));
    }
}
