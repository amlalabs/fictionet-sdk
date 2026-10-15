//! Bounded BER length prefixes, independent of tag and body policy.
//!
//! [`read_length`] borrows input and reports the prefix size without moving a
//! cursor. Callers decide whether indefinite lengths are allowed, bound the
//! announced body size, and translate errors into their protocol's errors.

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

/// Why a BER length prefix was refused.
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
}

fictionet::error_display!(Error, f, {
    Error::Reserved => f.write_str("reserved BER length octet"),
    Error::Octets => f.write_str("too many BER length octets"),
    Error::NonMinimal => f.write_str("BER length not in its shortest form"),
    Error::Overflow => f.write_str("BER length exceeds usize"),
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

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

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
