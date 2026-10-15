//! String format validation for `FormatPolicy::Assert`, and the format
//! examples that generation tries first.

use fictionet::stdlib::codec::ascii;

fn digits(bytes: &[u8]) -> Option<u32> {
    ascii::decimal(bytes, usize::MAX, u64::from(u32::MAX)).map(|n| n as u32)
}
fn date_parts(s: &str) -> Option<(u32, u32, u32)> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (year, month, day) = (digits(&b[..4])?, digits(&b[5..7])?, digits(&b[8..])?);
    let leap = fictionet::stdlib::codec::civil::is_leap_year(i64::from(year));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1..=12 => 31,
        _ => return None,
    };
    (day > 0 && day <= days).then_some((year, month, day))
}
// Returns whether this is a leap second and whether its UTC date is yesterday.
fn time_parts(s: &str) -> Option<(bool, bool)> {
    let b = s.as_bytes();
    if b.len() < 9 || b[2] != b':' || b[5] != b':' {
        return None;
    }
    let (hour, minute, second) = (digits(&b[..2])?, digits(&b[3..5])?, digits(&b[6..8])?);
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut at = 8;
    if b.get(at) == Some(&b'.') {
        at += 1;
        let first = at;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if first == at {
            return None;
        }
    }
    let zone = b.get(at..)?;
    let offset = match zone {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let (h, m) = (digits(&[*h1, *h2])?, digits(&[*m1, *m2])?);
            if h > 23 || m > 59 {
                return None;
            }
            (h as i32 * 60 + m as i32) * if *sign == b'-' { -1 } else { 1 }
        }
        _ => return None,
    };
    let utc = hour as i32 * 60 + minute as i32 - offset;
    if second == 60 && utc.rem_euclid(1440) != 1439 {
        return None;
    }
    Some((second == 60, utc < 0))
}
fn hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn email(s: &str) -> bool {
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || local.len() > 64 || s.len() > 254 {
        return false;
    }
    let valid_local =
        if let Some(quoted) = local.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            let mut bytes = quoted.bytes();
            let mut valid = true;
            while let Some(b) = bytes.next() {
                if b == b'\\' {
                    valid &= bytes.next().is_some_and(|b| (32..=126).contains(&b));
                } else {
                    valid &= (32..=126).contains(&b) && b != b'"';
                }
            }
            valid
        } else {
            local.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&b))
            })
        };
    let valid_domain = if let Some(ip) = domain.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
    {
        if ip.get(..5).is_some_and(|s| s.eq_ignore_ascii_case("IPv6:")) {
            ip[5..].parse::<std::net::Ipv6Addr>().is_ok()
        } else {
            ip.parse::<std::net::Ipv4Addr>().is_ok()
        }
    } else {
        hostname(domain)
    };
    valid_local && valid_domain
}
fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~".contains(&b)
}
fn sub_delim(b: u8) -> bool {
    b"!$&'()*+,;=".contains(&b)
}
fn uri_component(s: &str, extra: &[u8]) -> bool {
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            if !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|b| b.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !(unreserved(b) || sub_delim(b) || extra.contains(&b)) {
            return false;
        }
    }
    true
}
fn uri(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return false;
    }
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    if !uri_component(query, b"/?@:") || !uri_component(fragment, b"/?@:") {
        return false;
    }
    let path = if let Some(rest) = path.strip_prefix("//") {
        let (authority, path) = rest
            .find('/')
            .map_or((rest, ""), |i| (&rest[..i], &rest[i..]));
        let host = if let Some((user, host)) = authority.rsplit_once('@') {
            if !uri_component(user, b":") {
                return false;
            }
            host
        } else {
            authority
        };
        let port = if let Some(ip) = host.strip_prefix('[') {
            let Some((ip, tail)) = ip.split_once(']') else {
                return false;
            };
            let valid = if let Some(future) = ip.strip_prefix(['v', 'V']) {
                future.split_once('.').is_some_and(|(version, address)| {
                    !version.is_empty()
                        && version.bytes().all(|b| b.is_ascii_hexdigit())
                        && !address.is_empty()
                        && address
                            .bytes()
                            .all(|b| unreserved(b) || sub_delim(b) || b == b':')
                })
            } else {
                ip.parse::<std::net::Ipv6Addr>().is_ok()
            };
            if !valid {
                return false;
            }
            if tail.is_empty() {
                ""
            } else if let Some(port) = tail.strip_prefix(':') {
                port
            } else {
                return false;
            }
        } else {
            let (host, port) = host.split_once(':').unwrap_or((host, ""));
            if !uri_component(host, b"") {
                return false;
            }
            port
        };
        if !port.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        path
    } else {
        path
    };
    uri_component(path, b"/:@")
}
pub(super) fn valid_format(format: &str, s: &str) -> bool {
    match format {
        "date" => date_parts(s).is_some(),
        "time" => time_parts(s).is_some(),
        "date-time" => {
            let Some((_, month, day)) = s.get(..10).and_then(date_parts) else {
                return false;
            };
            if !matches!(s.as_bytes().get(10), Some(b'T' | b't')) {
                return false;
            }
            let Some((leap, yesterday)) = s.get(11..).and_then(time_parts) else {
                return false;
            };
            !leap
                || if yesterday {
                    matches!((month, day), (1 | 7, 1))
                } else {
                    matches!((month, day), (6, 30) | (12, 31))
                }
        }
        "email" => email(s),
        "hostname" => hostname(s),
        "uri" => uri(s),
        "uuid" => {
            s.len() == 36
                && s.bytes().enumerate().all(|(i, b)| {
                    if matches!(i, 8 | 13 | 18 | 23) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                })
        }
        "ipv4" => s.parse::<std::net::Ipv4Addr>().is_ok(),
        "ipv6" => s.parse::<std::net::Ipv6Addr>().is_ok(),
        _ => true,
    }
}
fn hostname_example(n: usize) -> Option<String> {
    if !(1..=253).contains(&n) {
        return None;
    }
    let mut s = String::with_capacity(n);
    while s.len() < n {
        let remaining = n - s.len();
        let size = if remaining == 64 {
            62
        } else {
            remaining.min(63)
        };
        s.extend(std::iter::repeat_n('a', size));
        if s.len() < n {
            s.push('.');
        }
    }
    Some(s)
}
fn ipv4_example(n: usize) -> Option<String> {
    if !(7..=15).contains(&n) {
        return None;
    }
    let mut extra = n - 7;
    let mut parts = Vec::new();
    for _ in 0..4 {
        let width = extra.min(2);
        extra -= width;
        parts.push(["1", "10", "100"][width]);
    }
    Some(parts.join("."))
}
fn ipv6_example(n: usize) -> Option<String> {
    if n == 2 {
        return Some("::".into());
    }
    for groups in 1usize..=8 {
        let base = if groups == 8 { 15 } else { groups * 2 + 1 };
        if n >= base && n - base <= groups * 3 {
            let mut extra = n - base;
            let parts: Vec<_> = (0..groups)
                .map(|_| {
                    let add = extra.min(3);
                    extra -= add;
                    "1".repeat(add + 1)
                })
                .collect();
            return Some(parts.join(":") + if groups == 8 { "" } else { "::" });
        }
    }
    if (40..=45).contains(&n) {
        return Some(format!(
            "1111:1111:1111:1111:1111:1111:{}",
            ipv4_example(n - 30)?
        ));
    }
    None
}
pub(super) fn format_example(format: &str, low: usize, high: usize) -> Option<String> {
    let sample = match format {
        "date-time" => "2000-01-01T00:00:00Z",
        "date" => "2000-01-01",
        "time" => "00:00:00Z",
        "email" => "a@example.test",
        "uuid" => "00000000-0000-4000-8000-000000000000",
        "uri" => "https://example.test/",
        "ipv4" => "192.0.2.1",
        "ipv6" => "2001:db8::1",
        "hostname" => "example.test",
        _ => return None,
    };
    if (low..=high).contains(&sample.len()) {
        return Some(sample.into());
    }
    let minimum = match format {
        "date-time" => 22,
        "time" => 11,
        "email" => 3,
        "uri" | "ipv6" => 2,
        "ipv4" => 7,
        "hostname" => 1,
        _ => return None,
    };
    let n = low.max(minimum);
    if n > high {
        return None;
    }
    let s = match format {
        "date-time" | "time" => format!(
            "{}.{}Z",
            sample.strip_suffix('Z')?,
            "0".repeat(n - sample.len() - 1)
        ),
        "email" if n <= 254 => {
            let local = (n - 2).min(64);
            format!("{}@{}", "a".repeat(local), hostname_example(n - local - 1)?)
        }
        "uri" => format!("a:{}", "x".repeat(n - 2)),
        "hostname" => hostname_example(n)?,
        "ipv4" => ipv4_example(n)?,
        "ipv6" => ipv6_example(n)?,
        _ => return None,
    };
    valid_format(format, &s).then_some(s)
}
