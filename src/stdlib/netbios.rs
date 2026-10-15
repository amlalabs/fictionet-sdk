//! NetBIOS name primitives shared by the name, datagram and session services.
//!
//! First-level encoding maps each byte of a 16-byte name to two letters
//! from `A` to `P`. An uncompressed wire name holds that 32-byte label,
//! optional scope labels, and a final zero. [`write_name`] appends one
//! complete name and leaves the destination unchanged on error.
//!
//! Name construction, compressed names and parsing errors belong to each
//! protocol. The name service retains its existing helper paths for
//! compatibility.
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

    const FRED: &[u8; 32] = b"EGFCEFEECACACACACACACACACACACACA";

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
