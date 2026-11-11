//! The QUIC versions this engine implements and how they negotiate
//!
//! Version 1 is [RFC 9000]. Version 2 is [RFC 9369], which changes only
//! the version number, the Long Header type bits, the Initial salt, the
//! HKDF labels and the Retry integrity key. The two are compatible in both
//! directions ([RFC 9368] section 2.2), so a server may answer a version 1
//! first flight in version 2. The draft versions are compatible with none.
//!
//! Every list here holds known versions inline, so negotiation never
//! allocates: a peer's list is reduced to the known versions it names.
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 9368]: https://www.rfc-editor.org/rfc/rfc9368.html
//! [RFC 9369]: https://www.rfc-editor.org/rfc/rfc9369.html

use std::fmt;

mod first_flight;
pub(crate) use first_flight::client_version_information;

/// QUIC version 1 ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html))
pub const QUIC_V1: u32 = 0x0000_0001;

/// QUIC version 2 ([RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html))
pub const QUIC_V2: u32 = 0x6b33_43cf;

/// Every version the engine can run, so a list of them fits inline.
const KNOWN: [u32; 8] = [
    QUIC_V1,
    QUIC_V2,
    0xff00_001d,
    0xff00_001e,
    0xff00_001f,
    0xff00_0020,
    0xff00_0021,
    0xff00_0022,
];

/// Whether the engine implements `version`.
pub fn is_known(version: u32) -> bool {
    KNOWN.contains(&version)
}

/// Whether a first flight of `from` converts to a first flight of `to`
/// (RFC 9368 section 2.2). Versions 1 and 2 are compatible with each other
/// (RFC 9369 section 4); every version is compatible with itself.
pub fn compatible(from: u32, to: u32) -> bool {
    from == to || matches!((from, to), (QUIC_V1, QUIC_V2) | (QUIC_V2, QUIC_V1))
}

/// How a version encodes the two Long Header packet type bits
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TypeBits {
    /// RFC 9000 section 17.2: Initial 0, 0-RTT 1, Handshake 2, Retry 3
    V1,
    /// RFC 9369 section 3.2: Initial 1, 0-RTT 2, Handshake 3, Retry 0
    V2,
}

impl TypeBits {
    pub(crate) fn of(version: u32) -> Self {
        match version {
            QUIC_V2 => Self::V2,
            _ => Self::V1,
        }
    }
}

/// An ordered list of distinct known versions, most preferred first
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VersionList {
    len: u8,
    versions: [u32; KNOWN.len()],
}

impl VersionList {
    /// The list with no versions
    pub const EMPTY: Self = Self {
        len: 0,
        versions: [0; KNOWN.len()],
    };

    /// A list of `versions` in the given order. Repeats keep their first
    /// position; a version the engine does not implement is an error.
    pub fn new(versions: &[u32]) -> Result<Self, UnknownVersion> {
        let mut list = Self::EMPTY;
        for &version in versions {
            if !list.push(version) {
                return Err(UnknownVersion(version));
            }
        }
        Ok(list)
    }

    /// The known versions of `versions` in their order, skipping the rest
    pub fn known(versions: impl IntoIterator<Item = u32>) -> Self {
        let mut list = Self::EMPTY;
        for version in versions {
            list.push(version);
        }
        list
    }

    /// Append `version` unless already present. Returns false, leaving the
    /// list unchanged, when the engine does not implement it.
    pub(crate) fn push(&mut self, version: u32) -> bool {
        if !is_known(version) {
            return false;
        }
        if !self.contains(version) {
            // Distinct known versions never exceed the capacity.
            self.versions[usize::from(self.len)] = version;
            self.len += 1;
        }
        true
    }

    /// The versions in order
    pub fn as_slice(&self) -> &[u32] {
        &self.versions[..usize::from(self.len)]
    }

    /// Whether `version` is in the list
    pub fn contains(&self, version: u32) -> bool {
        self.as_slice().contains(&version)
    }

    /// Whether the list is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The versions of this list a first flight of `chosen` converts to,
    /// keeping this list's order
    pub fn compatible_with(&self, chosen: u32) -> Self {
        Self::known(
            self.as_slice()
                .iter()
                .copied()
                .filter(|&version| compatible(chosen, version)),
        )
    }
    /// The first version of this list in `offered`: a client's choice from a
    /// Version Negotiation packet (RFC 9368 section 2.1)
    pub(crate) fn first_offered(&self, offered: impl Fn(u32) -> bool) -> Option<u32> {
        self.as_slice()
            .iter()
            .copied()
            .find(|&version| offered(version))
    }
}

impl fmt::Debug for VersionList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();
        for version in self.as_slice() {
            list.entry(&format_args!("{version:#x}"));
        }
        list.finish()
    }
}

/// A version the engine does not implement
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("QUIC version {0:#x} is not implemented")]
pub struct UnknownVersion(pub u32);

/// Version Information (RFC 9368 section 3): the sender's Chosen Version and
/// the known versions of its Available Versions, in order
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionInformation {
    /// The version the sender chose for the connection
    pub chosen: u32,
    /// The known versions the sender listed as available
    pub available: VersionList,
    /// Whether the sender also listed versions the engine does not implement
    pub unknown_available: bool,
}

impl VersionInformation {
    /// Whether the sender listed no Available Versions at all
    pub fn lists_nothing(&self) -> bool {
        self.available.is_empty() && !self.unknown_available
    }
}

/// A server's choice for a client's first flight in `original` (RFC 9368
/// section 2.3): the first version in the server's `preference` that the
/// first flight converts to and the client listed as available. Without
/// such a version the connection stays in `original`.
pub fn select_compatible(original: u32, preference: &[u32], client: &VersionList) -> u32 {
    preference
        .iter()
        .copied()
        .find(|&version| {
            is_known(version) && compatible(original, version) && client.contains(version)
        })
        .unwrap_or(original)
}

/// The downgrade check of RFC 9368 section 4 for a client that reacted to a
/// Version Negotiation packet: the client must have chosen `negotiated` had
/// it been offered the server's Available Versions plus `negotiated`.
pub fn negotiation_was_genuine(
    preference: &VersionList,
    server: &VersionInformation,
    negotiated: u32,
) -> bool {
    !server.lists_nothing()
        && preference
            .first_offered(|version| version == negotiated || server.available.contains(version))
            == Some(negotiated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_and_two_convert_both_ways_and_drafts_to_nothing_else() {
        assert!(compatible(QUIC_V1, QUIC_V2));
        assert!(compatible(QUIC_V2, QUIC_V1));
        for &version in &KNOWN {
            assert!(compatible(version, version));
            if version != QUIC_V1 && version != QUIC_V2 {
                assert!(!compatible(QUIC_V1, version));
                assert!(!compatible(version, QUIC_V2));
            }
        }
    }

    #[test]
    fn lists_keep_order_skip_repeats_and_refuse_unknown_versions() {
        let list = VersionList::new(&[QUIC_V2, QUIC_V1, QUIC_V2]).unwrap();
        assert_eq!(list.as_slice(), &[QUIC_V2, QUIC_V1]);
        assert_eq!(
            VersionList::new(&[QUIC_V1, 0x1a2a_3a4a]),
            Err(UnknownVersion(0x1a2a_3a4a))
        );
        let all = VersionList::known(KNOWN.iter().rev().copied().chain(KNOWN));
        assert_eq!(all.as_slice().len(), KNOWN.len());
        assert_eq!(all.as_slice()[0], KNOWN[KNOWN.len() - 1]);
        let peer = VersionList::known([0x0a0a_0a0a, QUIC_V2, 0x1234_5678]);
        assert_eq!(peer.as_slice(), &[QUIC_V2]);
    }

    #[test]
    fn the_server_upgrades_only_to_offered_compatible_versions() {
        let both = VersionList::new(&[QUIC_V2, QUIC_V1]).unwrap();
        let one = VersionList::new(&[QUIC_V1]).unwrap();
        assert_eq!(
            select_compatible(QUIC_V1, &[QUIC_V2, QUIC_V1], &both),
            QUIC_V2
        );
        assert_eq!(
            select_compatible(QUIC_V1, &[QUIC_V1, QUIC_V2], &both),
            QUIC_V1
        );
        assert_eq!(
            select_compatible(QUIC_V1, &[QUIC_V2, QUIC_V1], &one),
            QUIC_V1
        );
        assert_eq!(select_compatible(QUIC_V2, &[QUIC_V1], &both), QUIC_V1);
        let draft = 0xff00_001d;
        let with_draft = VersionList::new(&[draft, QUIC_V1]).unwrap();
        assert_eq!(
            select_compatible(QUIC_V1, &[draft, QUIC_V1], &with_draft),
            QUIC_V1
        );
        assert_eq!(select_compatible(QUIC_V1, &[0x1a2a_3a4a], &both), QUIC_V1);
    }

    #[test]
    fn a_forged_negotiation_toward_a_less_preferred_version_is_detected() {
        let preference = VersionList::new(&[QUIC_V2, QUIC_V1]).unwrap();
        let server = |available: &[u32], unknown_available| VersionInformation {
            chosen: QUIC_V1,
            available: VersionList::new(available).unwrap(),
            unknown_available,
        };
        let both = server(&[QUIC_V1, QUIC_V2], false);
        assert!(negotiation_was_genuine(&preference, &both, QUIC_V2));
        assert!(!negotiation_was_genuine(&preference, &both, QUIC_V1));
        assert!(negotiation_was_genuine(
            &preference,
            &server(&[QUIC_V1], false),
            QUIC_V1
        ));
        assert!(!negotiation_was_genuine(
            &preference,
            &server(&[], false),
            QUIC_V1
        ));
        // A server may list only versions this engine does not know.
        assert!(negotiation_was_genuine(
            &preference,
            &server(&[], true),
            QUIC_V1
        ));
    }
}
