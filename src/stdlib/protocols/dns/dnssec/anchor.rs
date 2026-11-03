//! Trust anchors: the DS records a validator trusts without proof.

use super::DigestType;
use super::keys::ds;
use super::rdata::{DNSKEY, DS};
use crate::stdlib::protocols::dns::label_count;
use crate::stdlib::protocols::dns::rr::Name;

/// The DS records a validator trusts for the zone at `owner`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The zone the anchor is for.
    pub owner: Name,
    /// DS records for the zone's key-signing keys.
    pub ds: Vec<DS>,
}

/// The trust anchors a validator starts from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Anchors(Vec<TrustAnchor>);

impl Anchors {
    /// The root zone's anchors as IANA publishes them: key-signing keys
    /// 20326 and 38696, both RSA/SHA-256, as SHA-256 DS records. The keys
    /// come from hickory's bundled copies.
    pub fn iana_root() -> Anchors {
        let bundled = hickory_proto::dnssec::TrustAnchors::default();
        let ds = (0..bundled.len())
            .filter_map(|index| bundled.get(index))
            .map(|key| {
                let key = DNSKEY::with_flags(257, key.clone());
                ds(&Name::root(), &key, DigestType::Sha256)
            })
            .collect();
        Anchors(vec![TrustAnchor {
            owner: Name::root(),
            ds,
        }])
    }

    /// These anchors.
    pub fn of(anchors: Vec<TrustAnchor>) -> Anchors {
        Anchors(anchors)
    }

    /// Every anchor.
    pub fn iter(&self) -> impl Iterator<Item = &TrustAnchor> {
        self.0.iter()
    }

    /// The deepest anchor with DS records whose zone holds `name`, or with
    /// `strictly_above`, whose zone holds it below its apex. A DS RRset
    /// sits on the parent side of its owner's cut, so it is checked
    /// against the anchor above its owner.
    pub(crate) fn closest(&self, name: &Name, strictly_above: bool) -> Option<&TrustAnchor> {
        self.0
            .iter()
            .filter(|anchor| !anchor.ds.is_empty() && anchor.owner.zone_of(name))
            .filter(|anchor| !strictly_above || anchor.owner != *name)
            .max_by_key(|anchor| label_count(&anchor.owner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closest_picks_the_deepest_anchor_holding_the_name() {
        let name = |text: &str| Name::from_ascii(text).unwrap();
        let mut anchors = Anchors::iana_root().0;
        let root_ds = anchors[0].ds[0].clone();
        anchors.push(TrustAnchor {
            owner: name("corp.example."),
            ds: vec![root_ds],
        });
        anchors.push(TrustAnchor {
            owner: name("empty.example."),
            ds: vec![],
        });
        let anchors = Anchors::of(anchors);
        let owner = |found: Option<&TrustAnchor>| found.map(|a| a.owner.to_string());
        assert_eq!(
            owner(anchors.closest(&name("www.corp.example."), false)),
            Some("corp.example.".into())
        );
        assert_eq!(
            owner(anchors.closest(&name("corp.example."), true)),
            Some(".".into())
        );
        assert_eq!(
            owner(anchors.closest(&name("a.empty.example."), false)),
            Some(".".into())
        );
        assert_eq!(
            owner(Anchors::default().closest(&name("example."), false)),
            None
        );
    }
}
