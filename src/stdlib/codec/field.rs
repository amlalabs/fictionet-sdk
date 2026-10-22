//! Fixed-point decimal text, space-padded printable ASCII fields and
//! [`Alpha`], the fixed-width field the market data protocols share.

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

/// A fixed-width text field: `N` bytes, spaces included. Padding is part
/// of the value, so fields round-trip byte for byte. [`new`](Self::new)
/// and the padded constructors accept only printable ASCII (0x20..=0x7e).
/// `From<[u8; N]>` keeps any bytes, for a protocol whose fields may hold
/// reserved or NUL-filled bytes; [`trimmed`](Self::trimmed) stops at the
/// first such byte.
///
/// ```
/// use fictionet::stdlib::codec::field::Alpha;
/// let stock = Alpha::<8>::right_padded("ZVZZT")?;
/// assert_eq!(stock.as_bytes(), b"ZVZZT   ");
/// assert_eq!(stock.trimmed(), "ZVZZT");
/// # Ok::<(), fictionet::stdlib::codec::field::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Alpha<const N: usize>([u8; N]);
impl<const N: usize> Alpha<N> {
    /// All spaces.
    pub const fn blank() -> Self {
        Self([b' '; N])
    }
    /// The field's exact bytes. Refuses a byte outside 0x20..=0x7e.
    pub fn new(bytes: [u8; N]) -> Result<Self, Error> {
        validate_printable(bytes).map(Self)
    }
    /// `text` padded on the left with spaces, as [`left_padded`] pads it.
    pub fn left_padded(text: &str) -> Result<Self, Error> {
        left_padded(text).map(Self)
    }
    /// `text` padded on the right with spaces, as [`right_padded`] pads it.
    pub fn right_padded(text: &str) -> Result<Self, Error> {
        right_padded(text).map(Self)
    }
    /// The field's bytes, padding included.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
    /// The text: the bytes up to the first one outside printable ASCII,
    /// without leading or trailing spaces.
    pub fn trimmed(&self) -> &str {
        let end = self
            .0
            .iter()
            .position(|b| !(0x20..=0x7e).contains(b))
            .unwrap_or(N);
        // Every byte before `end` is printable ASCII, so this is UTF-8.
        core::str::from_utf8(self.0.get(..end).unwrap_or_default())
            .unwrap_or_default()
            .trim_matches(' ')
    }
    /// Whether every byte is a space.
    pub fn is_blank(&self) -> bool {
        self.0.iter().all(|b| *b == b' ')
    }
    /// The same text in a field of `M` bytes, padded on the right. Refuses
    /// text that does not fit.
    pub fn resized<const M: usize>(&self) -> Result<Alpha<M>, Error> {
        Alpha::right_padded(self.trimmed())
    }
    /// Whether two fields hold the same text, ignoring padding.
    pub fn same_text(&self, other: &Self) -> bool {
        self.trimmed() == other.trimmed()
    }
    /// Whether two fields hold the same text, ignoring padding and ASCII
    /// case.
    pub fn matches(&self, other: &Self) -> bool {
        self.trimmed().eq_ignore_ascii_case(other.trimmed())
    }
}
impl<const N: usize> From<[u8; N]> for Alpha<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}
impl<const N: usize> fmt::Debug for Alpha<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0.escape_ascii())
    }
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
    fn alpha_fields() {
        assert_eq!(Alpha::<4>::left_padded("ab").unwrap().as_bytes(), b"  ab");
        assert_eq!(Alpha::<4>::right_padded("ab").unwrap().as_bytes(), b"ab  ");
        assert_eq!(Alpha::<2>::left_padded("abc"), Err(Error::Length));
        assert_eq!(Alpha::<2>::right_padded("\u{e9}"), Err(Error::Printable));
        assert_eq!(
            Alpha::<0>::right_padded("").unwrap().as_bytes(),
            &[] as &[u8]
        );
        for byte in 0..=u8::MAX {
            let bytes = [b' ', byte, b'~'];
            assert_eq!(Alpha::from(bytes).as_bytes(), &bytes);
            assert_eq!(
                Alpha::new(bytes).map(|a| *a.as_bytes()),
                validate_printable(bytes)
            );
        }
        let field = Alpha::new(*b" x  ").unwrap();
        assert_eq!(field.trimmed(), "x");
        assert_eq!(format!("{field:?}"), "\" x  \"");
        assert!(!field.is_blank());
        assert!(Alpha::<3>::blank().is_blank());
        // Bytes outside printable ASCII end the text and show escaped.
        let raw = Alpha::from(*b" A \0Z");
        assert_eq!(raw.trimmed(), "A");
        assert_eq!(format!("{raw:?}"), "\" A \\x00Z\"");
        assert_eq!(raw.resized::<2>().unwrap().as_bytes(), b"A ");
        assert_eq!(Alpha::from(*b"ABC").resized::<2>(), Err(Error::Length));
        assert!(Alpha::from(*b"Ab  ").same_text(&Alpha::from(*b"  Ab")));
        assert!(!Alpha::from(*b"Ab  ").same_text(&Alpha::from(*b"  aB")));
        assert!(Alpha::from(*b"Ab  ").matches(&Alpha::from(*b"  aB")));
        assert!(!Alpha::from(*b"Ab  ").matches(&Alpha::from(*b"  aC")));
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

    #[test]
    fn text_field_pads_validates_and_trims() {
        for (text, left, right) in [
            ("", *b"    ", *b"    "),
            ("AB", *b"  AB", *b"AB  "),
            (" A ", *b"  A ", *b" A  "),
            (" ~! ", *b" ~! ", *b" ~! "),
        ] {
            assert_eq!(Alpha::<4>::left_padded(text).unwrap().as_bytes(), &left);
            assert_eq!(Alpha::<4>::right_padded(text).unwrap().as_bytes(), &right);
        }
        assert_eq!(
            Alpha::<0>::left_padded("").unwrap().as_bytes(),
            &[] as &[u8]
        );
        assert_eq!(Alpha::<0>::right_padded("A"), Err(Error::Length));
        assert_eq!(Alpha::<4>::left_padded("ABCDE"), Err(Error::Length));
        for text in ["\0", "\t", "\n", "\u{1f}", "\u{7f}", "é", "🦀"] {
            assert_eq!(Alpha::<4>::left_padded(text), Err(Error::Printable));
            assert_eq!(Alpha::<4>::right_padded(text), Err(Error::Printable));
        }
        for byte in 0..=u8::MAX {
            let bytes = [b' ', b'A', byte];
            if (b' '..=b'~').contains(&byte) {
                assert_eq!(Alpha::new(bytes).unwrap().as_bytes(), &bytes);
            } else {
                assert_eq!(Alpha::new(bytes), Err(Error::Printable));
            }
            assert_eq!(Alpha::from(bytes).as_bytes(), &bytes);
        }
        assert_eq!(Alpha::new(*b" A ").unwrap().trimmed(), "A");
        assert_eq!(Alpha::from(*b" A \0Z").trimmed(), "A");
        assert!(Alpha::<3>::blank().is_blank());
    }

    #[test]
    fn protocols_keep_their_alpha_rules() {
        use fictionet::stdlib::codec::Wire;
        use fictionet::stdlib::protocols::{cboe_pitch, itch, moldudp64, ouch, soupbintcp};
        // A NUL in an alpha field: Nasdaq's protocols refuse the message,
        // Cboe's keeps the byte.
        fn nul_in(bytes: &mut [u8], field: &[u8]) {
            let at = bytes.windows(field.len()).position(|w| w == field).unwrap();
            bytes[at] = 0;
        }
        let symbol = Alpha::right_padded("ZVZZT").unwrap();
        let add = itch::AddOrder {
            header: itch::Header {
                locate: 3,
                tracking: 0,
                timestamp: itch::Timestamp::new(1).unwrap(),
            },
            order_ref: 5,
            side: itch::Side::Sell,
            shares: 100,
            stock: symbol,
            price: itch::Price4(10_000),
        };
        let mut bytes = itch::Message::from(add).to_bytes().unwrap();
        nul_in(&mut bytes, symbol.as_bytes());
        assert_eq!(
            <itch::Message as Wire>::parse(&bytes),
            Err(itch::Error::Field)
        );
        let enter = ouch::EnterOrder {
            user_ref: 1,
            side: ouch::Side::Buy,
            quantity: 10,
            symbol,
            price: ouch::Price(10_000),
            time_in_force: b'0',
            display: b'Y',
            capacity: b'A',
            intermarket_sweep: b'N',
            cross_type: b'N',
            cl_ord_id: Alpha::right_padded("A1").unwrap(),
            options: ouch::Options::default(),
        };
        let mut bytes = enter.to_bytes().unwrap();
        nul_in(&mut bytes, symbol.as_bytes());
        assert_eq!(
            <ouch::Inbound as Wire>::parse(&bytes),
            Err(ouch::Error::Field)
        );
        let login = soupbintcp::Login {
            username: Alpha::right_padded("ALICE").unwrap(),
            password: Alpha::right_padded("SECRET").unwrap(),
            session: Alpha::blank(),
            sequence: 1,
        };
        let mut bytes = soupbintcp::Packet::LoginRequest(login).to_bytes().unwrap();
        nul_in(&mut bytes, login.username.as_bytes());
        assert_eq!(
            <soupbintcp::Packet as Wire>::parse(&bytes),
            Err(soupbintcp::Error::Field)
        );
        let short = cboe_pitch::AddOrderShort {
            time_offset: 447_000,
            order_id: 5,
            side: cboe_pitch::Side::Buy,
            quantity: 737,
            symbol: symbol.resized().unwrap(),
            price: cboe_pitch::ShortPrice(1),
            flags: 1,
            extra: Vec::new(),
        };
        let mut bytes = cboe_pitch::Message::from(short).to_bytes().unwrap();
        nul_in(&mut bytes, b"ZVZZT ");
        let cboe_pitch::Message::AddOrderShort(parsed) =
            <cboe_pitch::Message as Wire>::parse(&bytes).unwrap()
        else {
            panic!("not an Add Order (short)")
        };
        assert_eq!(parsed.symbol.as_bytes(), b"\0VZZT ");
        assert_eq!(cboe_pitch::Message::from(parsed).to_bytes().unwrap(), bytes);

        // MoldUDP64's session field is its own type, padded on the left.
        for (text, bytes) in [
            ("", *b"          "),
            ("AB", *b"        AB"),
            ("0123456789", *b"0123456789"),
        ] {
            assert_eq!(
                moldudp64::Session::left_padded(text).unwrap().as_bytes(),
                &bytes
            );
        }
        for text in ["01234567890", "\0", "é"] {
            assert_eq!(
                moldudp64::Session::left_padded(text),
                Err(moldudp64::Error::Field)
            );
        }
        assert_eq!(
            moldudp64::Session::new(*b" A        ").unwrap().trimmed(),
            "A"
        );
        assert_eq!(
            moldudp64::Session::new(*b"A\0        "),
            Err(moldudp64::Error::Field)
        );
    }
}
