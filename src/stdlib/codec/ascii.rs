//! ASCII helpers shared by text codecs.

extern crate alloc;

use alloc::vec::Vec;

/// Returns the value of an ASCII hex digit in either case.
#[inline]
pub fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Returns the lowercase ASCII digit for the low four bits of `value`.
#[inline]
pub fn hex_lower(value: u8) -> u8 {
    b"0123456789abcdef"[usize::from(value & 15)]
}

/// Returns the uppercase ASCII digit for the low four bits of `value`.
#[inline]
pub fn hex_upper(value: u8) -> u8 {
    b"0123456789ABCDEF"[usize::from(value & 15)]
}

/// Returns whether a byte is an HTTP token character.
#[inline]
pub fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// Whether a byte is a SIP `token` character (RFC 3261 section 25.1).
///
/// Percent signs are ordinary token bytes. This does not validate escapes.
#[inline]
pub fn is_sip_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&b)
}

/// Removes leading and trailing ASCII spaces and tabs.
#[inline]
pub fn trim_ows(mut b: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = b {
        b = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = b {
        b = rest;
    }
    b
}

/// Removes leading and trailing ASCII spaces and tabs from text.
#[inline]
pub fn trim_ows_str(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// Reads one or more unsigned ASCII digits, allowing leading zeros and enforcing both bounds.
#[inline]
pub fn decimal(b: &[u8], max_digits: usize, max: u64) -> Option<u64> {
    if b.is_empty() || b.len() > max_digits {
        return None;
    }
    let mut n = 0u64;
    for &c in b {
        let d = c.checked_sub(b'0').filter(|&d| d < 10)?;
        n = n.checked_mul(10)?.checked_add(u64::from(d))?;
        if n > max {
            return None;
        }
    }
    Some(n)
}

/// Appends decoded bytes up to `max_len` total, preserving malformed escapes and optionally turning plus into space.
pub fn percent_decode_into(bytes: &[u8], plus: bool, out: &mut Vec<u8>, max_len: usize) {
    let mut i = 0;
    while i < bytes.len() && out.len() < max_len {
        let b = bytes[i];
        if b == b'%'
            && let (Some(h), Some(l)) = (
                bytes.get(i + 1).and_then(|&c| hex_value(c)),
                bytes.get(i + 2).and_then(|&c| hex_value(c)),
            )
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(if plus && b == b'+' { b' ' } else { b });
        i += 1;
    }
}

/// Decodes percent escapes, preserving plus and refusing malformed escapes.
pub fn percent_decode_strict(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut it = bytes.iter().copied();
    while let Some(b) = it.next() {
        if b == b'%' {
            out.push(hex_value(it.next()?)? << 4 | hex_value(it.next()?)?);
        } else {
            out.push(b);
        }
    }
    Some(out)
}

/// Checks that every byte is allowed or belongs to a `%` escape with two hex digits.
///
/// `allowed` is called only for unescaped bytes. A percent sign always starts
/// an escape, even if `allowed` would accept it. Escaped bytes are not decoded
/// or checked by `allowed`. Nothing is normalized, including literal plus signs.
///
/// This checks the whole slice without allocating or changing a caller's cursor.
/// Empty input is valid. There is no length limit; callers enforce their own
/// bounds and translate `false` to their protocol's error.
pub fn is_percent_encoded(bytes: &[u8], allowed: impl Fn(u8) -> bool) -> bool {
    let mut bytes = bytes.iter();
    while let Some(&b) = bytes.next() {
        if b == b'%' {
            if !bytes.next().is_some_and(u8::is_ascii_hexdigit)
                || !bytes.next().is_some_and(u8::is_ascii_hexdigit)
            {
                return false;
            }
        } else if !allowed(b) {
            return false;
        }
    }
    true
}

/// Whether a byte is an unreserved character or sub-delimiter in an RFC 3986 name.
pub fn is_uri_reg_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b)
}

/// Checks RFC 3986 component bytes, allowing the additional bytes in `extra`.
///
/// Unescaped bytes must be unreserved characters, sub-delimiters, or in `extra`.
/// Every `%` must have two following hex digits, even if `extra` contains `%`.
/// Escapes are validated without decoding or normalization. Literal `+` is allowed.
/// This uses [`is_percent_encoded`]: it accepts empty input, has no length limit,
/// and leaves the slice and any caller cursor unchanged. Callers check component
/// boundaries, nonempty requirements, and authority and port rules themselves.
///
/// ```
/// use fictionet::stdlib::codec::ascii::is_uri_component;
/// assert!(is_uri_component(b"name%2f+part", b""));
/// assert!(is_uri_component(b"/a:b?x=y", b":@/?"));
/// assert!(!is_uri_component(b"/path", b""));
/// assert!(!is_uri_component(b"name%2", b""));
/// ```
pub fn is_uri_component(bytes: &[u8], extra: &[u8]) -> bool {
    is_percent_encoded(bytes, |b| is_uri_reg_name_char(b) || extra.contains(&b))
}

/// Whether `s` is the inside of an RFC 3986 IP literal: an IPv6 address,
/// or `v`, hex digits, `.` and more characters for a future version.
pub fn is_uri_ip_literal(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix(['v', 'V']) {
        let Some((version, body)) = rest.split_once('.') else {
            return false;
        };
        return !version.is_empty()
            && version.bytes().all(|b| b.is_ascii_hexdigit())
            && !body.is_empty()
            && body.bytes().all(|b| is_uri_reg_name_char(b) || b == b':');
    }
    s.parse::<std::net::Ipv6Addr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_and_tokens() {
        for c in 0..=255u8 {
            assert_eq!(hex_value(c).map(u32::from), char::from(c).to_digit(16));
            assert_eq!(
                is_tchar(c),
                c.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&c)
            );
            assert_eq!(is_sip_token_byte(c), is_tchar(c) && !b"#$&^|".contains(&c));
        }
        for n in 0..16 {
            assert_eq!(hex_value(hex_lower(n)), Some(n));
            assert_eq!(hex_value(hex_upper(n)), Some(n));
        }
        assert_eq!(hex_lower(255), b'f');
        assert_eq!(hex_upper(255), b'F');
    }

    #[test]
    fn whitespace_and_decimal() {
        for s in ["", " \t", " \tx \t", "\rx\n", " é "] {
            assert_eq!(
                trim_ows(s.as_bytes()),
                s.trim_matches([' ', '\t']).as_bytes()
            );
            assert_eq!(trim_ows_str(s), s.trim_matches([' ', '\t']));
        }
        for s in [
            b"".as_slice(),
            b"+1",
            b"-1",
            b" 1",
            b"1 ",
            b"a",
            b"18446744073709551616",
        ] {
            assert_eq!(decimal(s, usize::MAX, u64::MAX), None);
        }
        assert_eq!(
            decimal(b"18446744073709551615", 20, u64::MAX),
            Some(u64::MAX)
        );
        assert_eq!(decimal(b"0001", 4, 1), Some(1));
        assert_eq!(decimal(b"0001", 3, 1), None);
        assert_eq!(decimal(b"2", 4, 1), None);
    }

    #[test]
    fn percent_validation() {
        assert!(is_percent_encoded(b"", |_| false));
        assert!(is_percent_encoded(b"%00%2f%FF", |_| false));
        assert!(!is_percent_encoded(b"+", |b| b == b' '));
        for invalid in [
            b"%".as_slice(),
            b"%4",
            b"%gg",
            b"%0G",
            b"%G0",
            b"%%41",
            b"%41%",
        ] {
            assert!(!is_percent_encoded(invalid, |_| true), "{invalid:?}");
        }
        let seen = core::cell::RefCell::new(Vec::new());
        assert!(is_percent_encoded(b"a+%00%2f%FFz", |b| {
            seen.borrow_mut().push(b);
            b.is_ascii_alphabetic() || b == b'+'
        }));
        assert_eq!(*seen.borrow(), b"a+z");
    }

    #[test]
    fn uri_components() {
        for valid in [b"".as_slice(), b"azAZ09-._~!$&'()*+,;=", b"%00%ff%2F+"] {
            assert!(is_uri_component(valid, b""), "{valid:?}");
        }
        for invalid in [
            b"%".as_slice(),
            b"%2",
            b"%gg",
            b" ",
            b"\0",
            b"\xff",
            b"[x]",
            b"a#b",
        ] {
            assert!(!is_uri_component(invalid, b":@/?"), "{invalid:?}");
        }
        for &extra in b":@/?" {
            assert!(!is_uri_component(&[extra], b""));
            assert!(is_uri_component(&[extra], &[extra]));
        }
        assert!(!is_uri_component(b"%", b"%"));
        assert!(is_uri_component(b"/a:b?x=y@z", b":@/?"));
    }

    #[test]
    fn percent_policies() {
        let mut out = Vec::new();
        percent_decode_into(b"+%2b%00%gg%", false, &mut out, usize::MAX);
        assert_eq!(out, b"++\0%gg%");
        out.clear();
        percent_decode_into(b"+%2brest", true, &mut out, 2);
        assert_eq!(out, b" +");
        assert_eq!(percent_decode_strict(b"+%2b%00"), Some(b"++\0".to_vec()));
        for b in [b"%".as_slice(), b"%a", b"%gg"] {
            assert_eq!(percent_decode_strict(b), None);
        }
        assert_eq!(percent_decode_strict(b""), Some(Vec::new()));
    }
}
