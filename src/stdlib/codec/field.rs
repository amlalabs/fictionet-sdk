//! Fixed-point decimal text and space-padded printable ASCII fields.

use core::fmt;

/// Invalid field text, width, or decimal scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid digits, excess fractional places, or an unrepresentable value or scale.
    Decimal,
    /// Text has more bytes than the fixed field can hold.
    Length,
    /// A byte is outside printable ASCII (0x20..=0x7e).
    Printable,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Decimal => "invalid fixed-point decimal",
            Self::Length => "text exceeds field width",
            Self::Printable => "field contains non-printable ASCII",
        })
    }
}
impl core::error::Error for Error {}

/// Validates and returns an exact field without changing its bytes.
/// Every byte must be printable ASCII (0x20..=0x7e), including spaces.
/// An empty array is valid. Invalid bytes return [`Error::Printable`].
///
/// ```
/// use fictionet::stdlib::codec::field::validate_printable;
/// assert_eq!(validate_printable(*b" A~ ")?, *b" A~ ");
/// assert!(validate_printable(*b"A\0").is_err());
/// # Ok::<(), fictionet::stdlib::codec::field::Error>(())
/// ```
pub fn validate_printable<const N: usize>(bytes: [u8; N]) -> Result<[u8; N], Error> {
    if bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
        Ok(bytes)
    } else {
        Err(Error::Printable)
    }
}

/// Pads `text` on the left with spaces to exactly `N` bytes.
/// Text longer than `N` bytes returns [`Error::Length`]. Otherwise, a byte
/// outside printable ASCII (0x20..=0x7e) returns [`Error::Printable`].
/// Existing spaces are preserved. Empty text produces all spaces, and
/// `N = 0` accepts only empty text. This does not consume a reader cursor.
///
/// ```
/// use fictionet::stdlib::codec::field::left_padded;
/// assert_eq!(left_padded::<4>("AB")?, *b"  AB");
/// # Ok::<(), fictionet::stdlib::codec::field::Error>(())
/// ```
pub fn left_padded<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    padded(text, true)
}

/// Pads `text` on the right with spaces to exactly `N` bytes.
/// Text longer than `N` bytes returns [`Error::Length`]. Otherwise, a byte
/// outside printable ASCII (0x20..=0x7e) returns [`Error::Printable`].
/// Existing spaces are preserved. Empty text produces all spaces, and
/// `N = 0` accepts only empty text. This does not consume a reader cursor.
///
/// ```
/// use fictionet::stdlib::codec::field::right_padded;
/// assert_eq!(right_padded::<4>("AB")?, *b"AB  ");
/// # Ok::<(), fictionet::stdlib::codec::field::Error>(())
/// ```
pub fn right_padded<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    padded(text, false)
}

fn padded<const N: usize>(text: &str, left: bool) -> Result<[u8; N], Error> {
    let pad = N.checked_sub(text.len()).ok_or(Error::Length)?;
    let start = if left { pad } else { 0 };
    let mut bytes = [b' '; N];
    bytes[start..start + text.len()].copy_from_slice(text.as_bytes());
    validate_printable(bytes)
}

/// Writes `raw` with exactly `places` fractional digits. Zero places writes an integer.
/// Returns an error if `10^places` exceeds `u64` or the output fails.
///
/// ```
/// use fictionet::stdlib::codec::field::write_decimal;
/// let mut out = String::new();
/// write_decimal(&mut out, 102500, 4)?;
/// assert_eq!(out, "10.2500");
/// # Ok::<(), core::fmt::Error>(())
/// ```
pub fn write_decimal(out: &mut impl fmt::Write, raw: u64, places: u32) -> fmt::Result {
    let scale = 10u64.checked_pow(places).ok_or(fmt::Error)?;
    if places == 0 {
        return write!(out, "{raw}");
    }
    write!(
        out,
        "{}.{:0width$}",
        raw / scale,
        raw % scale,
        width = places as usize
    )
}

/// Reads unsigned ASCII decimal text with at most `places` fractional digits.
/// Signs, empty parts, and trailing decimal points are rejected. The value and
/// `10^places` must fit in `u64`.
///
/// ```
/// use fictionet::stdlib::codec::field::parse_decimal;
/// assert_eq!(parse_decimal("10.25", 4)?, 102500);
/// assert!(parse_decimal("10.", 4).is_err());
/// # Ok::<(), fictionet::stdlib::codec::field::Error>(())
/// ```
pub fn parse_decimal(text: &str, places: u32) -> Result<u64, Error> {
    let scale = 10u64.checked_pow(places).ok_or(Error::Decimal)?;
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |t: &str| !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit());
    if !digits(whole)
        || (!fraction.is_empty() && !digits(fraction))
        || text.ends_with('.')
        || fraction.len() > places as usize
    {
        return Err(Error::Decimal);
    }
    let whole: u64 = whole.parse().map_err(|_| Error::Decimal)?;
    let mut frac: u64 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().map_err(|_| Error::Decimal)?
    };
    for _ in fraction.len()..places as usize {
        frac = frac.checked_mul(10).ok_or(Error::Decimal)?;
    }
    whole
        .checked_mul(scale)
        .and_then(|w| w.checked_add(frac))
        .ok_or(Error::Decimal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_bytes() {
        assert_eq!(validate_printable([]), Ok([]));
        for byte in 0..=u8::MAX {
            let bytes = [b' ', byte, b'~'];
            let expected = if (b' '..=b'~').contains(&byte) {
                Ok(bytes)
            } else {
                Err(Error::Printable)
            };
            assert_eq!(validate_printable(bytes), expected);
        }
    }

    #[test]
    fn printable_padding() {
        for (text, left, right) in [
            ("", *b"    ", *b"    "),
            ("AB", *b"  AB", *b"AB  "),
            (" A ", *b"  A ", *b" A  "),
            (" ~! ", *b" ~! ", *b" ~! "),
        ] {
            assert_eq!(left_padded(text), Ok(left));
            assert_eq!(right_padded(text), Ok(right));
        }
        assert_eq!(left_padded::<0>(""), Ok([]));
        assert_eq!(right_padded::<0>(""), Ok([]));
        assert_eq!(left_padded::<0>("A"), Err(Error::Length));
        assert_eq!(right_padded::<0>("A"), Err(Error::Length));
        for text in ["ABCDE", "ABCD\0", "ééé"] {
            assert_eq!(left_padded::<4>(text), Err(Error::Length));
            assert_eq!(right_padded::<4>(text), Err(Error::Length));
        }
        for text in ["\0", "\t", "\n", "\r", "\u{1f}", "\u{7f}", "é", "🦀"] {
            assert_eq!(left_padded::<4>(text), Err(Error::Printable));
            assert_eq!(right_padded::<4>(text), Err(Error::Printable));
        }
    }

    #[test]
    fn extremes() {
        for (places, max, text) in [
            (0, u64::MAX, "18446744073709551615"),
            (2, u64::MAX, "184467440737095516.15"),
            (4, u64::MAX, "1844674407370955.1615"),
            (8, u64::MAX, "184467440737.09551615"),
            (19, u64::MAX, "1.8446744073709551615"),
            (2, u64::from(u16::MAX), "655.35"),
            (4, u64::from(u32::MAX), "429496.7295"),
            (4, i64::MAX as u64, "922337203685477.5807"),
        ] {
            assert_eq!(parse_decimal(text, places), Ok(max));
            let mut out = String::new();
            write_decimal(&mut out, max, places).unwrap();
            assert_eq!(out, text);
            out.clear();
            write_decimal(&mut out, 0, places).unwrap();
            let zero = if places == 0 {
                "0".to_owned()
            } else {
                format!("0.{}", "0".repeat(places as usize))
            };
            assert_eq!(out, zero);
            assert_eq!(parse_decimal(&out, places), Ok(0));
        }
        assert_eq!(parse_decimal("0001.2", 4), Ok(12000));
        assert_eq!(parse_decimal("1", 8), Ok(100000000));
    }

    #[test]
    fn invalid_decimals() {
        for places in [0, 2, 4, 8, 19] {
            for text in [
                "",
                ".",
                "1.",
                ".1",
                "+1",
                "-1",
                "1.+1",
                "1.-1",
                " 1",
                "1 ",
                "1.2.3",
                "１",
                "1e2",
                "18446744073709551616",
            ] {
                assert_eq!(parse_decimal(text, places), Err(Error::Decimal), "{text}");
            }
            let text = format!("0.{}", "0".repeat(places as usize + 1));
            assert_eq!(parse_decimal(&text, places), Err(Error::Decimal));
        }
        for (places, text) in [
            (2, "184467440737095516.16"),
            (4, "1844674407370955.1616"),
            (8, "184467440737.09551616"),
            (19, "1.8446744073709551616"),
            (19, "2"),
        ] {
            assert_eq!(parse_decimal(text, places), Err(Error::Decimal));
        }
        for places in [20, u32::MAX] {
            assert_eq!(parse_decimal("0", places), Err(Error::Decimal));
            let mut out = String::from("price:");
            assert!(write_decimal(&mut out, 0, places).is_err());
            assert_eq!(out, "price:");
        }
    }
}
