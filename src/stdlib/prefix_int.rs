//! RFC 7541 prefix integers shared by HPACK and QPACK.
//!
//! Use [`Integer`] for a complete wire value. [`read`] and [`write`] handle
//! integers inside a larger header block while preserving its prefix bits.

use fictionet::stdlib::codec::Wire;

/// The most bytes read or written for one `u64`, including its prefix byte.
pub const MAX_BYTES: usize = 11;

/// Why an RFC 7541 prefix integer could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Input ends before the integer is complete.
    Truncated,
    /// Bytes follow a complete integer.
    Trailing,
    /// The value exceeds `u64` or needs more than [`MAX_BYTES`] bytes.
    Overflow,
    /// The prefix width is outside one through eight bits.
    Prefix,
    /// Flags overlap the integer prefix.
    Flags,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated prefix integer",
            Self::Trailing => "trailing prefix integer bytes",
            Self::Overflow => "prefix integer overflow",
            Self::Prefix => "invalid integer prefix width",
            Self::Flags => "flags overlap the integer prefix",
        })
    }
}
impl core::error::Error for Error {}

fn mask(prefix: u8) -> Result<u8, Error> {
    if !(1..=8).contains(&prefix) {
        return Err(Error::Prefix);
    }
    Ok(((1u16 << prefix) - 1) as u8)
}

/// Reads one RFC 7541 section 5.1 integer and returns its value and byte count.
///
/// `prefix` is the number of low bits used in the first byte, from one to eight.
/// Higher flag bits are ignored. Trailing bytes belong to the caller. Nonminimal
/// encodings are accepted within [`MAX_BYTES`]. Refuses invalid widths,
/// truncation, and overflow. Reads at most [`MAX_BYTES`] bytes and allocates none.
///
/// ```
/// use fictionet::stdlib::prefix_int;
/// assert_eq!(prefix_int::read(&[0x1f, 0x9a, 0x0a, 0xff], 5)?, (1337, 3));
/// # Ok::<(), prefix_int::Error>(())
/// ```
pub fn read(bytes: &[u8], prefix: u8) -> Result<(u64, usize), Error> {
    let mask = u64::from(mask(prefix)?);
    let mut value = u64::from(*bytes.first().ok_or(Error::Truncated)?) & mask;
    if value < mask {
        return Ok((value, 1));
    }
    for (i, shift) in (0..=63).step_by(7).enumerate() {
        let byte = *bytes.get(i + 1).ok_or(Error::Truncated)?;
        let low = u64::from(byte & 0x7f);
        if low > (u64::MAX >> shift) {
            return Err(Error::Overflow);
        }
        value = value.checked_add(low << shift).ok_or(Error::Overflow)?;
        if byte & 0x80 == 0 {
            return Ok((value, i + 2));
        }
    }
    Err(Error::Overflow)
}

/// Appends an RFC 7541 section 5.1 integer with the given prefix and flags.
///
/// Refuses widths outside one through eight and flags inside the prefix.
/// Leaves `out` unchanged on error. Appends at most [`MAX_BYTES`] bytes.
/// Protocols with a smaller integer limit must check that limit before calling.
pub fn write(out: &mut Vec<u8>, prefix: u8, flags: u8, value: u64) -> Result<(), Error> {
    let mask = mask(prefix)?;
    if flags & mask != 0 {
        return Err(Error::Flags);
    }
    let max = u64::from(mask);
    if value < max {
        out.push(flags | value as u8);
        return Ok(());
    }
    out.push(flags | mask);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest & 127) as u8 | 128);
        rest >>= 7;
    }
    out.push(rest as u8);
    Ok(())
}

/// An RFC 7541 integer with a prefix width from one to eight bits.
///
/// This shared wire form accepts all `u64` values. Enclosing protocols apply
/// their own limits. HPACK and QPACK use the same prefix representation.
///
/// ```
/// use fictionet::stdlib::{codec::Wire, prefix_int::Integer};
/// let integer = Integer::<5> { flags: 0x20, value: 1337 };
/// let bytes = integer.to_bytes()?;
/// assert_eq!(bytes, [0x3f, 0x9a, 0x0a]);
/// assert_eq!(Integer::<5>::parse(&bytes)?, integer);
/// # Ok::<(), fictionet::stdlib::prefix_int::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Integer<const PREFIX: u8> {
    /// Bits above the integer prefix.
    pub flags: u8,
    /// The unsigned integer. Protocol limits are checked by the enclosing format.
    pub value: u64,
}

impl<const PREFIX: u8> Wire for Integer<PREFIX> {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one integer. Refuses invalid widths, overflow, truncation,
    /// and trailing bytes. Preserves the flags above the prefix.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let (value, used) = read(bytes, PREFIX)?;
        if used != bytes.len() {
            return Err(Error::Trailing);
        }
        Ok(Self {
            flags: bytes.first().copied().ok_or(Error::Truncated)? & !mask(PREFIX)?,
            value,
        })
    }

    /// Appends one integer. Refuses invalid widths and flags inside the prefix.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write(out, PREFIX, self.flags, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn prefix_reads_and_failed_writes_preserve_their_boundaries() {
        let bytes = [0x3f, 0x9a, 0x0a, 0xff];
        assert_eq!(read(&bytes, 5), Ok((1337, 3)));
        for cut in 0..3 {
            assert_eq!(read(&bytes[..cut], 5), Err(Error::Truncated));
        }
        for prefix in 0..=u8::MAX {
            if (1..=8).contains(&prefix) {
                let mut out = vec![0xaa];
                write(&mut out, prefix, 0, u64::MAX).unwrap();
                assert!(out.len() <= MAX_BYTES + 1);
                assert_eq!(read(&out[1..], prefix), Ok((u64::MAX, out.len() - 1)));
                let before = out.clone();
                assert_eq!(write(&mut out, prefix, 1, 0), Err(Error::Flags));
                assert_eq!(out, before);
            } else {
                let mut out = vec![0xaa];
                assert_eq!(write(&mut out, prefix, 0, 0), Err(Error::Prefix));
                assert_eq!(out, [0xaa]);
                assert_eq!(read(&[0], prefix), Err(Error::Prefix));
            }
        }
    }

    #[test]
    fn integers_edges_overflow_and_strict_writers() {
        use fictionet::stdlib::codec::contract;
        assert_eq!(Integer::<5>::parse(&hex("0a")).unwrap().value, 10);
        assert_eq!(Integer::<5>::parse(&hex("1f9a0a")).unwrap().value, 1337);
        assert_eq!(Integer::<8>::parse(&hex("2a")).unwrap().value, 42);
        for value in [0, 30, 31, 32, 127, 255, 256, u32::MAX as u64, u64::MAX] {
            contract::check_wire_value(&Integer::<1> { flags: 0xfe, value });
            contract::check_wire_value(&Integer::<5> { flags: 0xa0, value });
            contract::check_wire_value(&Integer::<8> { flags: 0, value });
        }
        assert_eq!(Integer::<5>::parse(&[31]), Err(Error::Truncated));
        assert_eq!(Integer::<5>::parse(&[0, 0]), Err(Error::Trailing));
        assert_eq!(Integer::<5>::parse(&[0xff; 12]), Err(Error::Overflow));
        assert_eq!(
            Integer::<5>::parse(&hex("1fffffffffffffffffff01")),
            Err(Error::Overflow)
        );
        assert_eq!(
            Integer::<5>::parse(&hex("1f80808080808080808002")),
            Err(Error::Overflow)
        );
        // Nonminimal encodings are permitted, within the fixed integer byte bound.
        assert_eq!(Integer::<5>::parse(&hex("1f8000")).unwrap().value, 31);
        contract::check_wire_value(&Integer::<0> { flags: 0, value: 0 });
        contract::check_wire_value(&Integer::<9> { flags: 0, value: 0 });
        contract::check_wire_value(&Integer::<8> { flags: 1, value: 0 });
    }
}
