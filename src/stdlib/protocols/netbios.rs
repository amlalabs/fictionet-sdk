//! NetBIOS name primitives shared by the name, datagram and session services.
//!
//! First-level encoding maps each byte of a 16-byte name to two letters
//! from `A` to `P`. An uncompressed wire name holds that 32-byte label,
//! optional scope labels, and a final zero. [`write_name`] appends one
//! complete name and leaves the destination unchanged on error.
//!
//! Protocols choose where to truncate text before calling [`name_bytes`].
//! [`read_name`] reads an uncompressed prefix with caller-supplied errors.
//! Compressed names stay in the name service, which retains its existing
//! helper paths for compatibility.
//!
//! ```
//! use fictionet::stdlib::netbios::{decode_first_level, encode_first_level, write_name};
//!
//! let name = *b"FRED            ";
//! let label = encode_first_level(&name);
//! assert_eq!(&label, b"EGFCEFEECACACACACACACACACACACACA");
//! assert_eq!(decode_first_level(&label), Some(name));
//! let mut wire = Vec::new();
//! write_name(&mut wire, &name, &[b"NETBIOS".to_vec()]).unwrap();
//! assert_eq!(&wire[33..], b"\x07NETBIOS\x00");
//! let prefix = fictionet::stdlib::netbios::read_name(&wire, "truncated", "invalid").unwrap();
//! assert_eq!(prefix.bytes, name);
//! assert_eq!(prefix.len, wire.len());
//! ```

/// The length of a NetBIOS name: 15 characters and a suffix byte.
pub const NAME_LEN: usize = 16;
/// The length of a NetBIOS name in the first-level encoding.
pub const ENCODED_LEN: usize = 2 * NAME_LEN;
/// The longest label in a name's scope.
pub const MAX_LABEL: usize = 63;
/// The longest name on the wire: every label with its length byte, and
/// the zero byte that ends the name.
pub const MAX_NAME_LEN: usize = 255;

/// Uppercases ASCII letters in the first 15 bytes, pads with spaces, and
/// sets the suffix. Other bytes are kept. Callers that require a UTF-8
/// character boundary must cut their input at that boundary first.
pub fn name_bytes(name: &[u8], suffix: u8) -> [u8; NAME_LEN] {
    let mut bytes = [b' '; NAME_LEN];
    for (slot, b) in bytes.iter_mut().zip(name.iter().take(NAME_LEN - 1)) {
        *slot = b.to_ascii_uppercase();
    }
    bytes[NAME_LEN - 1] = suffix;
    bytes
}

/// The wildcard name: `*` followed by zero bytes, including the suffix.
pub fn wildcard_bytes() -> [u8; NAME_LEN] {
    let mut bytes = [0u8; NAME_LEN];
    bytes[0] = b'*';
    bytes
}

/// Splits text at dots and skips empty labels. Other labels are kept as
/// given; their lengths are checked when writing the name.
pub fn dotted_labels(text: &str) -> Vec<Vec<u8>> {
    text.split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.as_bytes().to_vec())
        .collect()
}

/// The first 15 bytes without trailing spaces. The suffix is excluded;
/// zero bytes and other non-space bytes are kept.
pub fn base(bytes: &[u8; NAME_LEN]) -> &[u8] {
    let chars = &bytes[..NAME_LEN - 1];
    let end = chars.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
    &chars[..end]
}

/// Writes bytes as text. Backslashes and bytes outside printable ASCII
/// are escaped as `\xNN`, with lowercase hex digits. Output errors are
/// returned after any text already written.
pub fn write_text(out: &mut impl std::fmt::Write, bytes: &[u8]) -> std::fmt::Result {
    for &b in bytes {
        if (0x20..0x7f).contains(&b) && b != b'\\' {
            write!(out, "{}", b as char)?;
        } else {
            write!(out, "\\x{b:02x}")?;
        }
    }
    Ok(())
}

/// Writes a name as Windows tools print it, such as `FILES<20>`, with
/// scope labels after dots. Name and scope bytes use [`write_text`]; the
/// suffix uses uppercase hex digits. Output errors keep earlier text.
pub fn write_display(
    out: &mut impl std::fmt::Write,
    bytes: &[u8; NAME_LEN],
    scope: &[Vec<u8>],
) -> std::fmt::Result {
    write_text(out, base(bytes))?;
    write!(out, "<{:02X}>", bytes[NAME_LEN - 1])?;
    for label in scope {
        out.write_str(".")?;
        write_text(out, label)?;
    }
    Ok(())
}

/// An uncompressed name and the number of wire bytes it occupies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamePrefix {
    /// The decoded 16-byte name, including its suffix.
    pub bytes: [u8; NAME_LEN],
    /// Scope labels, without their length bytes or the terminal zero.
    pub scope: Vec<Vec<u8>>,
    /// Bytes through the terminal zero. Bytes after this are not inspected.
    pub len: usize,
}

/// Reads an uncompressed name from the start of `b` without moving a cursor.
/// The caller advances by [`NamePrefix::len`] only on success.
///
/// Returns `truncated` if a length byte or label is missing. Returns `invalid`
/// for a first label other than 32 letters from `A` to `P`, a scope label
/// above [`MAX_LABEL`] (including compression pointers), or a name above
/// [`MAX_NAME_LEN`]. Length limits are checked before fetching label bytes;
/// first-level letters are checked only once all 32 are present.
pub fn read_name<E: Copy>(b: &[u8], truncated: E, invalid: E) -> Result<NamePrefix, E> {
    let first = *b.first().ok_or(truncated)?;
    if usize::from(first) != ENCODED_LEN {
        return Err(invalid);
    }
    let label = b.get(1..1 + ENCODED_LEN).ok_or(truncated)?;
    let bytes = decode_first_level(label).ok_or(invalid)?;
    let mut at = 1 + ENCODED_LEN;
    let mut scope = Vec::new();
    loop {
        let len = usize::from(*b.get(at).ok_or(truncated)?);
        if len == 0 {
            at += 1;
            break;
        }
        // The label, its length byte, and the final zero must fit.
        if len > MAX_LABEL || at + 1 + len + 1 > MAX_NAME_LEN {
            return Err(invalid);
        }
        let label = b.get(at + 1..at + 1 + len).ok_or(truncated)?;
        scope.push(label.to_vec());
        at += 1 + len;
    }
    Ok(NamePrefix {
        bytes,
        scope,
        len: at,
    })
}

/// Why an uncompressed name could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An empty or oversized scope label, or a name above [`MAX_NAME_LEN`].
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("invalid NetBIOS name or scope"),
        }
    }
}

impl std::error::Error for Error {}

/// The first-level encoding of a 16-byte NetBIOS name: each byte becomes
/// two letters, `A` plus its high half, then `A` plus its low half.
#[inline]
pub fn encode_first_level(name: &[u8; NAME_LEN]) -> [u8; ENCODED_LEN] {
    let mut out = [0u8; ENCODED_LEN];
    for (i, b) in name.iter().enumerate() {
        out[2 * i] = b'A' + (b >> 4);
        out[2 * i + 1] = b'A' + (b & 0x0f);
    }
    out
}

/// The 16-byte name a first-level label encodes. It returns `None` unless
/// the label is 32 bytes, each an uppercase letter from `A` to `P`.
#[inline]
pub fn decode_first_level(label: &[u8]) -> Option<[u8; NAME_LEN]> {
    if label.len() != ENCODED_LEN {
        return None;
    }
    let half = |c: u8| {
        if (b'A'..=b'P').contains(&c) {
            Some(c - b'A')
        } else {
            None
        }
    };
    let mut out = [0u8; NAME_LEN];
    for (i, pair) in label.as_chunks::<2>().0.iter().enumerate() {
        out[i] = half(pair[0])? << 4 | half(pair[1])?;
    }
    Some(out)
}

/// Appends labels and the final zero to an unfinished name in `out`.
/// `out` must contain only that name, with room for its final zero.
/// Each label must have 1 to [`MAX_LABEL`] bytes and leave room within
/// [`MAX_NAME_LEN`] for the final zero, counting bytes already in `out`.
/// Errors leave earlier labels in `out`.
pub fn write_labels<'a>(
    out: &mut Vec<u8>,
    labels: impl Iterator<Item = &'a [u8]>,
) -> Result<(), Error> {
    for label in labels {
        if label.is_empty() || label.len() > MAX_LABEL || out.len() + label.len() + 2 > MAX_NAME_LEN
        {
            return Err(Error::Unwritable);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    Ok(())
}

/// Appends an uncompressed NetBIOS name and scope.
/// Refuses empty or oversized labels and names above [`MAX_NAME_LEN`].
/// Errors leave the destination unchanged.
pub fn write_name(
    dst: &mut Vec<u8>,
    bytes: &[u8; NAME_LEN],
    scope: &[Vec<u8>],
) -> Result<(), Error> {
    let mut out = Vec::with_capacity(ENCODED_LEN + 2);
    out.push(ENCODED_LEN as u8);
    out.extend_from_slice(&encode_first_level(bytes));
    write_labels(&mut out, scope.iter().map(Vec::as_slice))?;
    dst.extend_from_slice(&out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::nbns::Name;
    use fictionet::stdlib::{nbdgm, nbns, nbss};

    const FRED: &[u8; 32] = b"EGFCEFEECACACACACACACACACACACACA";

    #[test]
    fn adapter_construction_and_display() {
        for (text, bytes, session_bytes) in [
            ("", *b"               \x20", *b"               \x20"),
            ("Fred", *b"FRED           \x20", *b"FRED           \x20"),
            (
                "abcdefghijklmnop",
                *b"ABCDEFGHIJKLMNO\x20",
                *b"ABCDEFGHIJKLMNO\x20",
            ),
            (
                "café",
                *b"CAF\xc3\xa9          \x20",
                *b"CAF\xc3\xa9          \x20",
            ),
            (
                "abcdefghijklmn大",
                *b"ABCDEFGHIJKLMN\xe5\x20",
                *b"ABCDEFGHIJKLMN \x20",
            ),
            (
                "😀😀😀😀",
                *b"\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x20",
                *b"\xf0\x9f\x98\x80\xf0\x9f\x98\x80\xf0\x9f\x98\x80   \x20",
            ),
        ] {
            let ns = Name::new(text, 0x20);
            let dgm = nbdgm::Name::new(text, 0x20);
            let ss = nbss::Name::new(text, 0x20);
            assert_eq!(ns.bytes, bytes);
            assert_eq!(dgm.bytes, bytes);
            assert_eq!(ss.bytes, session_bytes);
            assert_eq!(ns.name(), dgm.name());
            assert_eq!(ss.base(), base(&session_bytes));
            assert_eq!(Name::parse(&ns.to_bytes().unwrap()), Ok(ns));
            assert_eq!(nbdgm::Name::parse(&dgm.to_bytes().unwrap()), Ok(dgm));
            assert_eq!(nbss::Name::parse(&ss.to_bytes().unwrap()), Ok(ss));
        }

        let ns = Name::new("a\\\0é", 0xaf).with_scope(".CoRp..é.\\.");
        let dgm = nbdgm::Name::new("a\\\0é", 0xaf).with_scope(".CoRp..é.\\.");
        assert_eq!(
            ns.scope,
            vec![b"CoRp".to_vec(), b"\xc3\xa9".to_vec(), b"\\".to_vec()]
        );
        assert_eq!(dgm.scope, ns.scope);
        let display = "A\\x5c\\x00\\xc3\\xa9<AF>.CoRp.\\xc3\\xa9.\\x5c";
        assert_eq!(ns.to_string(), display);
        assert_eq!(dgm.to_string(), display);
        let mut out = String::new();
        write_display(&mut out, &ns.bytes, &ns.scope).unwrap();
        assert_eq!(out, display);
        assert_eq!(
            nbns::RrName::domain(".CoRp..é.\\.").to_string(),
            "CoRp.\\xc3\\xa9.\\x5c"
        );
        assert_eq!(Name::wildcard().bytes, *b"*\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(nbdgm::Name::wildcard().bytes, Name::wildcard().bytes);
        assert_eq!(Name::wildcard().name().len(), 15);
        assert_eq!(nbdgm::Name::wildcard().name().len(), 15);
    }

    #[test]
    fn adapter_wire_parity_and_prefix_length() {
        let scopes = [
            vec![],
            vec![b"NETBIOS".to_vec(), b"COM".to_vec()],
            vec![b"\0\xff\\".to_vec()],
            vec![
                vec![b'A'; 63],
                vec![b'B'; 63],
                vec![b'C'; 63],
                vec![b'D'; 28],
            ],
        ];
        for byte in 0..=255u8 {
            for scope in &scopes {
                let bytes = [byte; NAME_LEN];
                let ns = Name {
                    bytes,
                    scope: scope.clone(),
                };
                let dgm = nbdgm::Name {
                    bytes,
                    scope: scope.clone(),
                };
                let ss = nbss::Name {
                    bytes,
                    scope: scope.clone(),
                };
                let mut wire = vec![32];
                wire.extend_from_slice(&[b'A' + byte / 16, b'A' + byte % 16].repeat(16));
                for label in scope {
                    wire.push(label.len() as u8);
                    wire.extend_from_slice(label);
                }
                wire.push(0);
                assert_eq!(ns.to_bytes().unwrap(), wire);
                assert_eq!(dgm.to_bytes().unwrap(), wire);
                assert_eq!(ss.to_bytes().unwrap(), wire);
                assert_eq!(Name::parse(&wire), Ok(ns));
                assert_eq!(nbdgm::Name::parse(&wire), Ok(dgm));
                assert_eq!(nbss::Name::parse(&wire), Ok(ss));

                let len = wire.len();
                wire.extend_from_slice(&[0xc0, 0xff]);
                assert_eq!(
                    read_name(&wire, "truncated", "invalid"),
                    Ok(NamePrefix {
                        bytes,
                        scope: scope.clone(),
                        len,
                    })
                );
                assert_eq!(Name::parse(&wire), Err(nbns::Error::Trailing(2)));
                assert_eq!(nbdgm::Name::parse(&wire), Err(nbdgm::Error::Trailing(2)));
                assert_eq!(
                    nbss::Name::parse(&wire),
                    Err(nbss::Error::Trailing { remaining: 2 })
                );
            }
        }
    }

    #[test]
    fn adapter_error_policy() {
        let wire = Name::new("Fred", 0x20)
            .with_scope("NETBIOS.COM")
            .to_bytes()
            .unwrap();
        for end in 0..wire.len() {
            let prefix = &wire[..end];
            assert_eq!(read_name(prefix, "truncated", "invalid"), Err("truncated"));
            assert_eq!(Name::parse(prefix), Err(nbns::Error::Truncated));
            assert_eq!(nbdgm::Name::parse(prefix), Err(nbdgm::Error::Truncated));
            assert_eq!(nbss::Name::parse(prefix), Err(nbss::Error::Name));
        }

        let mut too_long = wire[..33].to_vec();
        for n in [63, 63, 63, 29] {
            too_long.push(n);
            too_long.extend(std::iter::repeat_n(b'x', usize::from(n)));
        }
        too_long.push(0);
        let mut bad_scope = wire[..33].to_vec();
        bad_scope.push(64);
        let mut bad_letters = wire[..34].to_vec();
        bad_letters[1] = b'Q';
        bad_letters[33] = 0;
        for (bad, ns_error) in [
            (vec![0], nbns::Error::BadFirstLevel),
            (vec![31], nbns::Error::Truncated),
            (vec![0xc0, 0], nbns::Error::BadPointer(0)),
            (bad_scope, nbns::Error::BadLabel(64)),
            (bad_letters, nbns::Error::BadFirstLevel),
            (too_long, nbns::Error::NameTooLong),
        ] {
            assert_eq!(read_name(&bad, "truncated", "invalid"), Err("invalid"));
            assert_eq!(Name::parse(&bad), Err(ns_error));
            assert_eq!(nbdgm::Name::parse(&bad), Err(nbdgm::Error::Name));
            assert_eq!(nbss::Name::parse(&bad), Err(nbss::Error::Name));
        }

        for scope in [vec![vec![]], vec![vec![0; 64]], vec![vec![0; 63]; 4]] {
            let bytes = *b"FRED            ";
            let mut dst = b"prefix".to_vec();
            assert_eq!(
                Name {
                    bytes,
                    scope: scope.clone()
                }
                .write(&mut dst),
                Err(nbns::Error::Unwritable)
            );
            assert_eq!(dst, b"prefix");
            assert_eq!(
                nbdgm::Name {
                    bytes,
                    scope: scope.clone()
                }
                .write(&mut dst),
                Err(nbdgm::Error::Unwritable)
            );
            assert_eq!(dst, b"prefix");
            assert_eq!(
                nbss::Name { bytes, scope }.write(&mut dst),
                Err(nbss::Error::Unwritable)
            );
            assert_eq!(dst, b"prefix");
        }
    }

    #[test]
    fn labels_append_and_keep_progress_on_error() {
        let mut out = Vec::new();
        write_labels(&mut out, std::iter::empty()).unwrap();
        assert_eq!(out, b"\x00");

        let mut out = b"\x07NETBIOS".to_vec();
        write_labels(&mut out, [b"COM".as_slice()].into_iter()).unwrap();
        assert_eq!(out, b"\x07NETBIOS\x03COM\x00");

        let mut out = b"\x07NETBIOS".to_vec();
        assert_eq!(
            write_labels(&mut out, [b"COM".as_slice(), b""].into_iter()),
            Err(Error::Unwritable)
        );
        assert_eq!(out, b"\x07NETBIOS\x03COM");
    }

    #[test]
    fn first_level_encoding_example() {
        // RFC 1001 section 14.1: "FRED" padded with spaces.
        let fred = Name::new("Fred", 0x20);
        assert_eq!(&fred.to_bytes().unwrap()[1..1 + ENCODED_LEN], FRED);
        assert_eq!(decode_first_level(FRED), Some(fred.bytes));
        assert_eq!(
            &Name::wildcard().to_bytes().unwrap()[1..1 + ENCODED_LEN],
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        for b in 0..=255u8 {
            let name = Name {
                bytes: [b; NAME_LEN],
                scope: Vec::new(),
            };
            assert_eq!(Name::parse(&name.to_bytes().unwrap()), Ok(name));
        }
        // Wrong lengths and letters outside A to P.
        assert_eq!(decode_first_level(&FRED[..31]), None);
        assert_eq!(
            decode_first_level(b"QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            None
        );
        assert_eq!(
            decode_first_level(b"aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            None
        );
    }

    #[test]
    fn uncompressed_name_limits_and_compatibility() {
        for b in 0..=255u8 {
            let name = [b; NAME_LEN];
            assert_eq!(decode_first_level(&encode_first_level(&name)), Some(name));
        }

        let name = *b"FRED            ";
        let mut scope = vec![vec![b'x'; MAX_LABEL]; 3];
        scope.push(vec![b'y'; 28]);
        let prefix = vec![0xff; MAX_NAME_LEN];
        let mut out = prefix.clone();
        write_name(&mut out, &name, &scope).unwrap();
        assert_eq!(out.len(), prefix.len() + MAX_NAME_LEN);
        assert_eq!(&out[..prefix.len()], &prefix);
        assert_eq!(&out[prefix.len() + 1..prefix.len() + 33], FRED);
        assert_eq!(Name::parse(&out[prefix.len()..]).unwrap().scope, scope);
        let mut legacy = prefix.clone();
        fictionet::stdlib::nbns::write_name(&mut legacy, &name, &scope).unwrap();
        assert_eq!(legacy, out);

        scope.last_mut().unwrap().push(b'y');
        for invalid in [vec![Vec::new()], vec![vec![0; MAX_LABEL + 1]], scope] {
            let mut out = prefix.clone();
            assert_eq!(
                write_name(&mut out, &name, &invalid),
                Err(Error::Unwritable)
            );
            assert_eq!(out, prefix);
            let result: Result<(), fictionet::stdlib::nbns::Error> =
                fictionet::stdlib::nbns::write_name(&mut out, &name, &invalid);
            assert_eq!(result, Err(fictionet::stdlib::nbns::Error::Unwritable));
            assert_eq!(out, prefix);
        }
    }
}
