//! Bounded BER lengths and minimal base-128 integers, independent of protocol policy.
//!
//! [`read_length`] borrows input and reports the prefix size without moving a
//! cursor. Callers decide whether indefinite lengths are allowed, bound the
//! announced body size, and translate errors into their protocol's errors.

extern crate alloc;
use alloc::vec::Vec;

/// Limits and canonicality for a BER length prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthPolicy {
    /// The most long-form octets allowed after the first octet. Zero permits
    /// only short and indefinite forms. BER itself permits at most 126.
    pub max_octets: usize,
    /// Require the shortest definite form: no leading zero octet, and no
    /// long form for a value below 128. This does not forbid indefinite form.
    pub minimal: bool,
}

/// An announced length and the size of its prefix, excluding the tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthPrefix {
    /// The definite content length, or `None` for indefinite form.
    pub value: Option<usize>,
    /// The number of length octets, including the first octet.
    pub len: usize,
}

/// Why a BER length prefix or base-128 integer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The first octet is the reserved value 0xff.
    Reserved,
    /// The long form uses more octets than the policy permits.
    Octets,
    /// The definite length is not in its shortest form.
    NonMinimal,
    /// The complete definite length exceeds [`usize::MAX`].
    Overflow,
    /// A base-128 integer starts with a redundant zero continuation group.
    NonMinimalBase128,
    /// A base-128 integer exceeds the caller's maximum or [`u128::MAX`].
    Base128Limit,
}

fictionet::error_display!(Error, f, {
    Error::Reserved => f.write_str("reserved BER length octet"),
    Error::Octets => f.write_str("too many BER length octets"),
    Error::NonMinimal => f.write_str("BER length not in its shortest form"),
    Error::Overflow => f.write_str("BER length exceeds usize"),
    Error::NonMinimalBase128 => f.write_str("BER base-128 integer not in its shortest form"),
    Error::Base128Limit => f.write_str("BER base-128 integer exceeds limit"),
});

/// Reads a length prefix, returning `Ok(None)` when more octets are needed.
///
/// Reserved forms and octet counts over the policy limit fail on the first
/// octet. With `minimal`, a leading zero fails as soon as it is present.
/// Other minimality and overflow errors wait for the complete prefix, even
/// if an incomplete prefix already proves the value will overflow. Bytes
/// after the prefix are not inspected; the body need not be present.
/// Input is unchanged on every outcome. The caller advances by [`LengthPrefix::len`]
/// only when it accepts a prefix.
///
/// ```
/// use fictionet::stdlib::codec::ber::{LengthPolicy, LengthPrefix, read_length};
/// let policy = LengthPolicy { max_octets: 4, minimal: true };
/// assert_eq!(read_length(&[0x82, 1], policy), Ok(None));
/// assert_eq!(read_length(&[0x82, 1, 0], policy),
///     Ok(Some(LengthPrefix { value: Some(256), len: 3 })));
/// ```
pub fn read_length(b: &[u8], policy: LengthPolicy) -> Result<Option<LengthPrefix>, Error> {
    let Some(&first) = b.first() else {
        return Ok(None);
    };
    match first {
        0..=0x7f => Ok(Some(LengthPrefix {
            value: Some(usize::from(first)),
            len: 1,
        })),
        0x80 => Ok(Some(LengthPrefix {
            value: None,
            len: 1,
        })),
        0xff => Err(Error::Reserved),
        _ => {
            let n = usize::from(first & 0x7f);
            if n > policy.max_octets {
                return Err(Error::Octets);
            }
            let mut value = Some(0usize);
            for k in 0..n {
                let Some(&byte) = b.get(k + 1) else {
                    return Ok(None);
                };
                if policy.minimal && k == 0 && byte == 0 {
                    return Err(Error::NonMinimal);
                }
                value = value.and_then(|v| v.checked_mul(256)?.checked_add(usize::from(byte)));
            }
            let value = value.ok_or(Error::Overflow)?;
            if policy.minimal && value < 0x80 {
                return Err(Error::NonMinimal);
            }
            Ok(Some(LengthPrefix {
                value: Some(value),
                len: 1 + n,
            }))
        }
    }
}

/// A minimal base-128 integer and the size of its encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base128Prefix {
    /// The decoded unsigned value.
    pub value: u128,
    /// The number of octets, including the terminating octet.
    pub len: usize,
}

/// Reads one minimal base-128 integer, high groups first, at most `max`.
///
/// Returns `Ok(None)` for empty input or an unfinished value within the
/// limit. A leading 0x80 fails immediately. Overflow and values over `max`
/// fail at the first group that exceeds the limit, even without a terminator.
/// Bytes after the first octet with its top bit clear are not inspected.
/// Input is unchanged on every outcome. The caller advances by
/// [`Base128Prefix::len`] only when it accepts the value, and translates
/// incomplete input and errors into its own protocol's errors.
///
/// ```
/// use fictionet::stdlib::codec::ber::{Base128Prefix, read_base128};
/// assert_eq!(read_base128(&[0x81], 180), Ok(None));
/// assert_eq!(read_base128(&[0x81, 0x34, 0xff], 180),
///     Ok(Some(Base128Prefix { value: 180, len: 2 })));
/// ```
pub fn read_base128(b: &[u8], max: u128) -> Result<Option<Base128Prefix>, Error> {
    let mut value = 0u128;
    for (i, &byte) in b.iter().enumerate() {
        if i == 0 && byte == 0x80 {
            return Err(Error::NonMinimalBase128);
        }
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add(u128::from(byte & 0x7f)))
            .filter(|&v| v <= max)
            .ok_or(Error::Base128Limit)?;
        if byte & 0x80 == 0 {
            return Ok(Some(Base128Prefix { value, len: i + 1 }));
        }
    }
    Ok(None)
}

/// Appends `value` in minimal base 128, high groups first.
///
/// Every octet but the last has its top bit set. Zero uses one octet.
/// A value over `max` returns [`Error::Base128Limit`] without changing `out`.
/// At most 19 octets are appended. Allocation follows [`Vec::extend_from_slice`];
/// callers needing fallible allocation must reserve space first.
pub fn write_base128(out: &mut Vec<u8>, mut value: u128, max: u128) -> Result<(), Error> {
    if value > max {
        return Err(Error::Base128Limit);
    }
    let mut tmp = [0u8; 19];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    let last = tmp.len() - 1;
    for b in &mut tmp[i..last] {
        *b |= 0x80;
    }
    out.extend_from_slice(&tmp[i..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn base128_vectors_and_limits() {
        let mut largest = vec![0xff; 19];
        largest[0] = 0x83;
        largest[18] = 0x7f;
        for (value, bytes) in [
            (0, &[0][..]),
            (127, &[0x7f]),
            (128, &[0x81, 0]),
            (180, &[0x81, 0x34]),
            (16383, &[0xff, 0x7f]),
            (16384, &[0x81, 0x80, 0]),
            (u32::MAX as u128, &[0x8f, 0xff, 0xff, 0xff, 0x7f]),
            (u32::MAX as u128 + 80, &[0x90, 0x80, 0x80, 0x80, 0x4f]),
            (u128::MAX, largest.as_slice()),
        ] {
            for max in [value, u128::MAX] {
                let mut out = vec![0x42];
                write_base128(&mut out, value, max).unwrap();
                assert_eq!(&out[1..], bytes);
                let mut input = bytes.to_vec();
                input.push(0x80);
                assert_eq!(
                    read_base128(&input, max),
                    Ok(Some(Base128Prefix {
                        value,
                        len: bytes.len()
                    }))
                );
                for end in 0..bytes.len() {
                    assert_eq!(read_base128(&bytes[..end], max), Ok(None));
                }
            }
            if value > 0 {
                assert_eq!(read_base128(bytes, value - 1), Err(Error::Base128Limit));
                let mut out = vec![0x42];
                assert_eq!(
                    write_base128(&mut out, value, value - 1),
                    Err(Error::Base128Limit)
                );
                assert_eq!(out, [0x42]);
            }
        }
    }

    #[test]
    fn base128_rejection_timing() {
        for b in [&[0x80][..], &[0x80, 0], &[0x80, 1], &[0x80, 0x81]] {
            for max in [0, u128::MAX] {
                assert_eq!(read_base128(b, max), Err(Error::NonMinimalBase128));
            }
        }
        assert_eq!(read_base128(&[0x81], 0), Err(Error::Base128Limit));
        assert_eq!(read_base128(&[0x81, 0x80], 127), Err(Error::Base128Limit));
        assert_eq!(read_base128(&[0x81, 0x80], 128), Ok(None));
        let mut over = [0x80; 19];
        over[0] = 0x84;
        assert_eq!(read_base128(&over[..18], u128::MAX), Ok(None));
        assert_eq!(read_base128(&over, u128::MAX), Err(Error::Base128Limit));
        over[18] = 0;
        assert_eq!(read_base128(&over, u128::MAX), Err(Error::Base128Limit));
    }

    #[test]
    fn length_vectors_across_policies() {
        for max_octets in [0, 4, 126, usize::MAX] {
            for minimal in [false, true] {
                let policy = LengthPolicy {
                    max_octets,
                    minimal,
                };
                for (b, value, len) in [
                    (&[0][..], Some(0), 1),
                    (&[127][..], Some(127), 1),
                    (&[0x80][..], None, 1),
                    (&[0x81, 128, 99][..], Some(128), 2),
                    (&[0x82, 1, 0][..], Some(256), 3),
                    (&[0x82, 0, 128][..], Some(128), 3),
                    (&[0x81, 0][..], Some(0), 2),
                    (&[0x81, 127][..], Some(127), 2),
                ] {
                    let expected = if len - 1 > max_octets {
                        Err(Error::Octets)
                    } else if minimal && len > 1 && (b[1] == 0 || value < Some(128)) {
                        Err(Error::NonMinimal)
                    } else {
                        Ok(Some(LengthPrefix { value, len }))
                    };
                    assert_eq!(read_length(b, policy), expected, "{b:?}, {policy:?}");
                }
                assert_eq!(read_length(&[], policy), Ok(None));
                assert_eq!(read_length(&[0xff], policy), Err(Error::Reserved));
            }
        }
    }

    #[test]
    fn incomplete_prefixes_and_error_timing() {
        let mut policy = LengthPolicy {
            max_octets: 4,
            minimal: true,
        };
        for b in [&[0x84][..], &[0x84, 1], &[0x84, 1, 0], &[0x84, 1, 0, 0]] {
            assert_eq!(read_length(b, policy), Ok(None));
        }
        assert_eq!(read_length(&[0x85], policy), Err(Error::Octets));
        assert_eq!(read_length(&[0x84, 0], policy), Err(Error::NonMinimal));
        policy.minimal = false;
        assert_eq!(read_length(&[0x84, 0], policy), Ok(None));
        policy.max_octets = 126;
        let mut b = [0; 127];
        b[0] = 0xfe;
        b[126] = 127;
        for end in 0..b.len() {
            assert_eq!(read_length(&b[..end], policy), Ok(None));
        }
        assert_eq!(
            read_length(&b, policy),
            Ok(Some(LengthPrefix {
                value: Some(127),
                len: 127
            }))
        );
    }

    #[test]
    fn representable_limit_and_overflow_wait_for_all_octets() {
        let policy = LengthPolicy {
            max_octets: 126,
            minimal: false,
        };
        let mut b = vec![0x80 | core::mem::size_of::<usize>() as u8];
        b.extend_from_slice(&usize::MAX.to_be_bytes());
        assert_eq!(
            read_length(&b, policy),
            Ok(Some(LengthPrefix {
                value: Some(usize::MAX),
                len: b.len()
            }))
        );
        let mut overflow = [0xff; 127];
        overflow[0] = 0xfe;
        for end in 0..overflow.len() {
            assert_eq!(read_length(&overflow[..end], policy), Ok(None));
        }
        assert_eq!(read_length(&overflow, policy), Err(Error::Overflow));
        b[0] += 1;
        b.insert(1, 1);
        b[2..].fill(0);
        assert_eq!(read_length(&b, policy), Err(Error::Overflow));
    }
}
