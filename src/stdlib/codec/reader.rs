//! Checked reads from a byte slice.

use core::fmt;

/// Reads a 2-byte big-endian integer at `at`.
/// Returns `None` if the full value is unavailable, including offset overflow.
#[inline]
pub fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_be_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// Reads a 3-byte big-endian integer at `at`.
/// Returns `None` if the full value is unavailable, including offset overflow.
#[inline]
pub fn be24(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(3)?;
    let &[a, b, c] = bytes.get(at..end)? else { return None; };
    Some(u32::from_be_bytes([0, a, b, c]))
}

/// Reads a 4-byte big-endian integer at `at`.
/// Returns `None` if the full value is unavailable, including offset overflow.
#[inline]
pub fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_be_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// Reads a 2-byte little-endian integer at `at`.
/// Returns `None` if the full value is unavailable, including offset overflow.
#[inline]
pub fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// Reads a 3-byte little-endian integer at `at`.
/// Returns `None` if the full value is unavailable, including offset overflow.
#[inline]
pub fn le24(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(3)?;
    let &[a, b, c] = bytes.get(at..end)? else { return None; };
    Some(u32::from_le_bytes([a, b, c, 0]))
}

/// Reads a 4-byte little-endian integer at `at`.
/// Returns `None` if the full value is unavailable, including offset overflow.
#[inline]
pub fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// Reads an 8-byte big-endian integer at `at`.
/// Returns `None` if the full value is unavailable, including offset overflow.
#[inline]
pub fn be64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_be_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// Reads an 8-byte little-endian integer at `at`.
/// Returns `None` if the full value is unavailable, including offset overflow.
#[inline]
pub fn le64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_le_bytes(bytes.get(at..end)?.try_into().ok()?))
}

/// Input ended inside a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Truncated;

impl fmt::Display for Truncated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("input ended inside a value")
    }
}
impl core::error::Error for Truncated {}

/// The number of unread bytes after a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trailing(pub usize);

impl fmt::Display for Trailing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} unread bytes after a value", self.0)
    }
}
impl core::error::Error for Trailing {}

/// A checked byte cursor whose failed reads leave its position unchanged.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// Starts at the first byte of `bytes`.
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Self { Self { bytes, position: 0 } }

    /// Returns the number of unread bytes.
    #[inline]
    pub fn remaining(&self) -> usize { self.bytes.len() - self.position }

    /// Returns the number of bytes consumed.
    #[inline]
    pub fn position(&self) -> usize { self.position }

    /// Reports whether every byte has been consumed.
    #[inline]
    pub fn is_empty(&self) -> bool { self.remaining() == 0 }

    /// Returns the next byte without consuming it.
    #[inline]
    pub fn peek_u8(&self) -> Option<u8> { self.bytes.get(self.position).copied() }

    /// Consumes `n` bytes or leaves the position unchanged on truncation.
    #[inline]
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Truncated> {
        if n > self.remaining() { return Err(Truncated); }
        let start = self.position;
        self.position += n;
        Ok(&self.bytes[start..self.position])
    }

    /// Skips `n` bytes or leaves the position unchanged on truncation.
    #[inline]
    pub fn skip(&mut self, n: usize) -> Result<(), Truncated> { self.take(n).map(|_| ()) }

    /// Consumes an array of `N` bytes.
    #[inline]
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Truncated> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Consumes one byte.
    #[inline]
    pub fn u8(&mut self) -> Result<u8, Truncated> { Ok(self.take(1)?[0]) }

    /// Consumes a u16 in big-endian order.
    #[inline]
    pub fn u16_be(&mut self) -> Result<u16, Truncated> { self.array().map(u16::from_be_bytes) }

    /// Consumes a u16 in little-endian order.
    #[inline]
    pub fn u16_le(&mut self) -> Result<u16, Truncated> { self.array().map(u16::from_le_bytes) }

    /// Consumes a u32 in big-endian order.
    #[inline]
    pub fn u32_be(&mut self) -> Result<u32, Truncated> { self.array().map(u32::from_be_bytes) }

    /// Consumes a u32 in little-endian order.
    #[inline]
    pub fn u32_le(&mut self) -> Result<u32, Truncated> { self.array().map(u32::from_le_bytes) }

    /// Consumes a u64 in big-endian order.
    #[inline]
    pub fn u64_be(&mut self) -> Result<u64, Truncated> { self.array().map(u64::from_be_bytes) }

    /// Consumes a u64 in little-endian order.
    #[inline]
    pub fn u64_le(&mut self) -> Result<u64, Truncated> { self.array().map(u64::from_le_bytes) }

    /// Consumes a i16 in big-endian order.
    #[inline]
    pub fn i16_be(&mut self) -> Result<i16, Truncated> { self.array().map(i16::from_be_bytes) }

    /// Consumes a i16 in little-endian order.
    #[inline]
    pub fn i16_le(&mut self) -> Result<i16, Truncated> { self.array().map(i16::from_le_bytes) }

    /// Consumes a i32 in big-endian order.
    #[inline]
    pub fn i32_be(&mut self) -> Result<i32, Truncated> { self.array().map(i32::from_be_bytes) }

    /// Consumes a i32 in little-endian order.
    #[inline]
    pub fn i32_le(&mut self) -> Result<i32, Truncated> { self.array().map(i32::from_le_bytes) }

    /// Consumes a i64 in big-endian order.
    #[inline]
    pub fn i64_be(&mut self) -> Result<i64, Truncated> { self.array().map(i64::from_be_bytes) }

    /// Consumes a i64 in little-endian order.
    #[inline]
    pub fn i64_le(&mut self) -> Result<i64, Truncated> { self.array().map(i64::from_le_bytes) }

    /// Consumes a f64 in big-endian order.
    #[inline]
    pub fn f64_be(&mut self) -> Result<f64, Truncated> { self.array().map(f64::from_be_bytes) }

    /// Consumes a f64 in little-endian order.
    #[inline]
    pub fn f64_le(&mut self) -> Result<f64, Truncated> { self.array().map(f64::from_le_bytes) }

    /// Consumes a signed byte.
    #[inline]
    pub fn i8(&mut self) -> Result<i8, Truncated> { self.u8().map(|b| b as i8) }

    /// Consumes a three-byte integer in big-endian order.
    #[inline]
    pub fn u24_be(&mut self) -> Result<u32, Truncated> {
        let [a, b, c] = self.array()?;
        Ok(u32::from_be_bytes([0, a, b, c]))
    }

    /// Consumes a three-byte integer in little-endian order.
    #[inline]
    pub fn u24_le(&mut self) -> Result<u32, Truncated> {
        let [a, b, c] = self.array()?;
        Ok(u32::from_le_bytes([a, b, c, 0]))
    }

    /// Consumes and returns every unread byte.
    #[inline]
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.bytes[self.position..];
        self.position = self.bytes.len();
        out
    }

    /// Checks that no unread bytes remain.
    #[inline]
    pub fn finish(&self) -> Result<(), Trailing> {
        if self.is_empty() { Ok(()) } else { Err(Trailing(self.remaining())) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_offsets_check_every_width_and_overflow() {
        let bytes = [0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        macro_rules! check {
            ($read:ident, $width:expr, $value:expr) => {{
                assert_eq!($read(&bytes, 1), Some($value));
                assert_eq!($read(&bytes[1..1 + $width], 0), Some($value));
                for len in 0..$width {
                    assert_eq!($read(&bytes[1..1 + len], 0), None);
                    assert_eq!($read(&bytes[..1 + len], 1), None);
                }
                for at in [bytes.len(), bytes.len() + 1, usize::MAX - 1, usize::MAX] {
                    assert_eq!($read(&bytes, at), None);
                    assert_eq!($read(&[], at), None);
                }
                assert_eq!($read(&[0; 8], 0), Some(0));
            }};
        }
        check!(be16, 2, 0x1234);
        check!(le16, 2, 0x3412);
        check!(be24, 3, 0x123456);
        check!(le24, 3, 0x563412);
        check!(be32, 4, 0x12345678);
        check!(le32, 4, 0x78563412);
        check!(be64, 8, 0x123456789abcdef0);
        check!(le64, 8, 0xf0debc9a78563412);
    }

    #[test]
    fn truncated_reads_keep_position() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u8(), Ok(1));
        let before = r.position();
        assert_eq!(r.take(usize::MAX), Err(Truncated));
        assert_eq!(r.skip(3), Err(Truncated));
        assert_eq!(r.array::<3>(), Err(Truncated));
        assert_eq!(r.u24_be(), Err(Truncated));
        assert_eq!(r.u24_le(), Err(Truncated));
        assert_eq!(r.u32_be(), Err(Truncated));
        assert_eq!(r.u32_le(), Err(Truncated));
        assert_eq!(r.u64_be(), Err(Truncated));
        assert_eq!(r.u64_le(), Err(Truncated));
        assert_eq!(r.position(), before);
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.peek_u8(), Some(2));
        assert_eq!(r.take(0), Ok(&[][..]));
        assert_eq!(r.u16_be(), Ok(0x0203));
        assert_eq!(r.u8(), Err(Truncated));
        assert_eq!(r.u16_be(), Err(Truncated));
        assert_eq!(r.u16_le(), Err(Truncated));
        assert_eq!(r.position(), 3);
        assert_eq!(r.peek_u8(), None);
    }

    #[test]
    fn widths_and_byte_orders() {
        macro_rules! number {
            ($be:ident, $le:ident, $value:expr) => {{
                let value = $value;
                assert_eq!(Reader::new(&value.to_be_bytes()).$be(), Ok(value));
                assert_eq!(Reader::new(&value.to_le_bytes()).$le(), Ok(value));
                let bytes = value.to_be_bytes();
                for n in 0..bytes.len() {
                    let mut r = Reader::new(&bytes[..n]);
                    assert_eq!(r.$be(), Err(Truncated));
                    assert_eq!(r.position(), 0);
                    assert_eq!(r.$le(), Err(Truncated));
                    assert_eq!(r.position(), 0);
                }
            }};
        }
        number!(u16_be, u16_le, 0x1234u16);
        number!(u32_be, u32_le, 0x1234_5678u32);
        number!(u64_be, u64_le, 0x1234_5678_9abc_def0u64);
        number!(i16_be, i16_le, -1234i16);
        number!(i32_be, i32_le, -1234567i32);
        number!(i64_be, i64_le, -12345678910i64);
        number!(f64_be, f64_le, -12.25f64);
        assert_eq!(Reader::new(&[0xff]).i8(), Ok(-1));
        assert_eq!(Reader::new(&[0x12, 0x34, 0x56]).u24_be(), Ok(0x123456));
        assert_eq!(Reader::new(&[0x56, 0x34, 0x12]).u24_le(), Ok(0x123456));
        assert_eq!(Reader::new(&[1, 2, 3]).array(), Ok([1, 2, 3]));
    }

    #[test]
    fn finish_counts_unread_bytes() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.finish(), Err(Trailing(3)));
        r.skip(1).unwrap();
        assert_eq!(r.finish(), Err(Trailing(2)));
        assert_eq!(r.position(), 1);
        assert_eq!(r.clone().rest(), &[2, 3]);
        assert_eq!(r.position(), 1);
        assert_eq!(r.rest(), &[2, 3]);
        assert_eq!(r.position(), 3);
        assert!(r.is_empty());
        assert_eq!(r.finish(), Ok(()));
        assert_eq!(r.rest(), &[]);
    }
}
