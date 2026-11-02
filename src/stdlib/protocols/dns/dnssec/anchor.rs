//! Trust anchors: the DS records a validator trusts without proof, and the
//! files a guest's own resolvers read them from.

use std::fmt::Write;

use super::DigestType;
use super::keys::ds;
use super::rdata::{DNSKEY, DS};
use crate::stdlib::protocols::dns::rr::Name;

/// The DS records a validator trusts for the zone at `owner`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The zone the anchor is for.
    pub owner: Name,
    /// DS records for the zone's key-signing keys.
    pub ds: Vec<DS>,
}

impl TrustAnchor {
    /// The anchor as a systemd-resolved positive trust anchor file, such
    /// as `/etc/dnssec-trust-anchors.d/root.positive`: one DS record per
    /// line in zone file syntax (dnssec-trust-anchors.d(5)).
    pub fn resolved_positive(&self) -> String {
        self.ds_lines()
    }

    /// The anchor as Unbound reads it from a trust anchor file, such as
    /// `/usr/share/dns/root.key` or `/var/lib/unbound/root.key`: DS records
    /// in zone file syntax, which Unbound's `auto-trust-anchor-file` takes
    /// as well as DNSKEY records.
    pub fn root_key(&self) -> String {
        self.ds_lines()
    }

    /// The anchor as a BIND `bind.keys` file, such as
    /// `/etc/bind/bind.keys`, which `delv` reads: a `trust-anchors`
    /// statement with one `initial-ds` entry per DS record, as BIND ships
    /// the root's.
    pub fn bind_keys(&self) -> String {
        let mut text = String::from("trust-anchors {\n");
        for ds in &self.ds {
            let _ = writeln!(
                text,
                "\t{} initial-ds {} {} {} \"{}\";",
                self.owner_text(),
                ds.key_tag(),
                u8::from(ds.algorithm()),
                u8::from(ds.digest_type()),
                hex_upper(ds.digest()),
            );
        }
        text.push_str("};\n");
        text
    }

    fn ds_lines(&self) -> String {
        let mut text = String::new();
        for ds in &self.ds {
            let _ = writeln!(
                text,
                "{} IN DS {} {} {} {}",
                self.owner_text(),
                ds.key_tag(),
                u8::from(ds.algorithm()),
                u8::from(ds.digest_type()),
                hex_upper(ds.digest()),
            );
        }
        text
    }

    fn owner_text(&self) -> String {
        let mut owner = self.owner.clone();
        owner.set_fqdn(true);
        owner.to_string()
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
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
            .filter(|anchor| !strictly_above || anchor.owner.num_labels() < name.num_labels())
            .max_by_key(|anchor| anchor.owner.num_labels())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iana_root_renders_the_real_root_anchor_files() {
        let anchors = Anchors::iana_root();
        let root = anchors.iter().next().unwrap();
        let positive = root.resolved_positive();
        assert!(positive.contains(
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"
        ));
        assert!(positive.contains(
            ". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16\n"
        ));
        assert_eq!(root.root_key(), positive);
        let bind = root.bind_keys();
        assert!(bind.starts_with("trust-anchors {\n"));
        assert!(bind.contains(
            "\t. initial-ds 20326 8 2 \"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\";\n"
        ));
        assert!(bind.ends_with("};\n"));
    }

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
