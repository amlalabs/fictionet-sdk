//! Zone keys: the private half that signs, and the DNSKEY and DS records
//! that publish the public half.
//!
//! A [`ZoneKey`] is a private key from [`services::keys`] with the DNSKEY
//! flags and algorithm it signs under. It signs deterministically, so a
//! seeded run makes the same records every time. Anything else that can
//! sign, such as a key held outside the world, implements [`Sign`]. A
//! [`KeySet`] holds every key of one zone: a key-signing and a
//! zone-signing key, or two of either during a rollover.
//!
//! [`services::keys`]: fictionet::stdlib::services::keys

use std::fmt;
use std::sync::Arc;

use super::anchor::TrustAnchor;
use super::policy::AlgorithmPolicy;
use super::rdata::{DNSKEY, DNSSECRData, DS};
use super::{Algorithm, DigestType};
use crate::stdlib::protocols::dns::rr::{Name, RData, Record, RecordSet, RecordType};
use fictionet::Entropy;
use fictionet::stdlib::services::keys::{Key, KeyKind};
use hickory_proto::dnssec::{PublicKey, PublicKeyBuf};
use p256::ecdsa::signature::Signer;
use rsa::traits::PublicKeyParts;

/// The flags field of a DNSKEY record (RFC 4034 §2.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyFlags(pub u16);

impl KeyFlags {
    /// A zone-signing key: the Zone Key bit alone, 256.
    pub const ZSK: KeyFlags = KeyFlags(0x0100);
    /// A key-signing key: the Zone Key and Secure Entry Point bits, 257.
    pub const KSK: KeyFlags = KeyFlags(0x0101);

    /// Whether the Zone Key bit is set. Only such keys may verify zone
    /// data (RFC 4034 §2.1.1).
    pub fn zone_key(self) -> bool {
        self.0 & 0x0100 != 0
    }

    /// Whether the Secure Entry Point bit is set. It marks the keys a
    /// parent's DS records are meant to point at, and validators ignore it
    /// (RFC 4034 §2.1.1).
    pub fn secure_entry_point(self) -> bool {
        self.0 & 0x0001 != 0
    }

    /// Whether the REVOKE bit is set (RFC 5011 §3). A revoked key verifies
    /// nothing.
    pub fn revoked(self) -> bool {
        self.0 & 0x0080 != 0
    }
}

/// Why a key could not be read or a DS record could not be made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The bytes are not a PKCS#8 key this code reads.
    Pkcs8,
    /// The key cannot sign with the algorithm asked for, such as a P-256
    /// key for algorithm 8.
    WrongAlgorithm(Algorithm),
    /// The RSA modulus is outside the sizes RFC 5702 §2 allows for the
    /// algorithm: 512 to 4096 bits for RSA/SHA-256, 1024 to 4096 for
    /// RSA/SHA-512.
    ModulusSize(usize),
    /// The policy does not let this world create DS records with this
    /// digest type, as RFC 9905 forbids SHA-1.
    DigestNotForDelegation(u8),
    /// The policy does not let this world create records for keys of this
    /// algorithm, as RFC 9905 forbids algorithms 5 and 7.
    AlgorithmNotForSigning(u8),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Pkcs8 => f.write_str("the bytes are not a PKCS#8 key"),
            KeyError::WrongAlgorithm(algorithm) => {
                write!(f, "the key cannot sign with {algorithm:?}")
            }
            KeyError::ModulusSize(bits) => {
                write!(f, "a {bits}-bit RSA modulus is outside RFC 5702's sizes")
            }
            KeyError::DigestNotForDelegation(digest) => {
                write!(f, "the policy forbids DS digest type {digest}")
            }
            KeyError::AlgorithmNotForSigning(algorithm) => {
                write!(f, "the policy forbids DNSKEY algorithm {algorithm}")
            }
        }
    }
}

impl std::error::Error for KeyError {}

/// Something that signs for a zone: it publishes one DNSKEY and signs
/// to-be-signed bytes with the matching private key.
pub trait Sign: Send + Sync {
    /// The DNSKEY record data this key publishes.
    fn dnskey(&self) -> DNSKEY;
    /// The signature over `tbs`, the to-be-signed bytes of RFC 4034
    /// §3.1.8.1, in the form the DNSKEY's algorithm puts in an RRSIG.
    fn sign(&self, tbs: &[u8]) -> Vec<u8>;
}

/// A private zone key with its DNSKEY flags and algorithm.
pub struct ZoneKey {
    key: Key,
    algorithm: Algorithm,
    dnskey: DNSKEY,
}

impl ZoneKey {
    /// A new key for `algorithm`, drawn from `entropy`, so a seeded run
    /// makes the same key every time. RSA keys are 2048 bits. RSA
    /// generation is slow; a world that needs the same RSA key on every run
    /// stores it once with [`ZoneKey::to_pkcs8`].
    pub fn generate(entropy: &dyn Entropy, algorithm: Algorithm, flags: KeyFlags) -> ZoneKey {
        let kind = match algorithm {
            Algorithm::RsaSha256 | Algorithm::RsaSha512 => KeyKind::Rsa2048,
            Algorithm::EcdsaP256Sha256 => KeyKind::P256,
            Algorithm::EcdsaP384Sha384 => KeyKind::P384,
            Algorithm::Ed25519 => KeyKind::Ed25519,
        };
        ZoneKey::new(Key::generate(entropy, kind), algorithm, flags)
            .expect("a generated key fits its algorithm")
    }

    /// Reads a PKCS#8 DER key that signs with `algorithm`. RSA keys carry
    /// no hash, so the algorithm says which one they sign with.
    pub fn from_pkcs8(
        der: &[u8],
        algorithm: Algorithm,
        flags: KeyFlags,
    ) -> Result<ZoneKey, KeyError> {
        let key = Key::from_pkcs8(der).map_err(|_| KeyError::Pkcs8)?;
        ZoneKey::new(key, algorithm, flags)
    }

    /// The key as PKCS#8 DER.
    pub fn to_pkcs8(&self) -> Vec<u8> {
        self.key.to_pkcs8()
    }

    /// The algorithm the key signs with.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn new(key: Key, algorithm: Algorithm, flags: KeyFlags) -> Result<ZoneKey, KeyError> {
        let public = match (&key, algorithm) {
            (Key::Rsa(rsa), Algorithm::RsaSha256 | Algorithm::RsaSha512) => {
                let bits = rsa.n().bits();
                let least = if algorithm == Algorithm::RsaSha256 {
                    512
                } else {
                    1024
                };
                if !(least..=4096).contains(&bits) {
                    return Err(KeyError::ModulusSize(bits));
                }
                rsa_public_key(rsa)
            }
            // RFC 6605 §4: the point's x and y, without SEC1's leading 0x04.
            (Key::P256(ecdsa), Algorithm::EcdsaP256Sha256) => {
                ecdsa.verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec()
            }
            (Key::P384(ecdsa), Algorithm::EcdsaP384Sha384) => {
                ecdsa.verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec()
            }
            // RFC 8080 §3: the 32-octet public key.
            (Key::Ed25519(ed), Algorithm::Ed25519) => ed.public_key().to_vec(),
            _ => return Err(KeyError::WrongAlgorithm(algorithm)),
        };
        let dnskey = DNSKEY::with_flags(flags.0, PublicKeyBuf::new(public, algorithm.hickory()));
        Ok(ZoneKey {
            key,
            algorithm,
            dnskey,
        })
    }
}

/// An RSA public key as RFC 3110 §2 writes it in a DNSKEY: the exponent's
/// length in one octet, or a zero octet and two more past 255, then the
/// exponent and the modulus, neither with leading zeros.
fn rsa_public_key(key: &rsa::RsaPrivateKey) -> Vec<u8> {
    let exponent = key.e().to_bytes_be();
    let mut public = Vec::new();
    match u8::try_from(exponent.len()) {
        Ok(len) => public.push(len),
        Err(_) => {
            public.push(0);
            public.extend_from_slice(&(exponent.len() as u16).to_be_bytes());
        }
    }
    public.extend_from_slice(&exponent);
    public.extend_from_slice(&key.n().to_bytes_be());
    public
}

impl Sign for ZoneKey {
    fn dnskey(&self) -> DNSKEY {
        self.dnskey.clone()
    }

    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        match &self.key {
            // RFC 5702 §3: RSASSA-PKCS1-v1_5, which needs no randomness.
            Key::Rsa(rsa) => {
                let (padding, hash) = if self.algorithm == Algorithm::RsaSha512 {
                    (
                        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha512>(),
                        ring::digest::digest(&ring::digest::SHA512, tbs),
                    )
                } else {
                    (
                        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                        ring::digest::digest(&ring::digest::SHA256, tbs),
                    )
                };
                rsa.sign(padding, hash.as_ref())
                    .expect("RFC 5702 moduli hold a PKCS#1 v1.5 signature")
            }
            // RFC 6605 §4: r and s, each as long as the curve's order.
            // p256 and p384 pick the nonce as RFC 6979 describes, from the
            // key and the message, so signing draws no randomness.
            Key::P256(ecdsa) => {
                let signature: p256::ecdsa::Signature = ecdsa.sign(tbs);
                signature.to_bytes().to_vec()
            }
            Key::P384(ecdsa) => {
                let signature: p384::ecdsa::Signature = ecdsa.sign(tbs);
                signature.to_bytes().to_vec()
            }
            // RFC 8080 §4: Ed25519 is deterministic by construction.
            Key::Ed25519(ed) => ed.sign(tbs),
        }
    }
}

impl fmt::Debug for ZoneKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneKey")
            .field("algorithm", &self.algorithm)
            .field("flags", &KeyFlags(self.dnskey.flags()))
            .field("tag", &key_tag(&self.dnskey))
            .finish_non_exhaustive()
    }
}

/// Every key of one zone.
#[derive(Clone, Default)]
pub struct KeySet {
    /// The keys, each of which signs every RRset of the zone.
    pub keys: Vec<Arc<dyn Sign>>,
}

impl KeySet {
    /// The zone's DNSKEY RRset at `apex`.
    pub fn dnskey_rrset(&self, apex: &Name, ttl: u32) -> RecordSet {
        let mut set = RecordSet::with_ttl(apex.clone(), RecordType::DNSKEY, ttl);
        for key in &self.keys {
            let rdata = RData::DNSSEC(DNSSECRData::DNSKEY(key.dnskey()));
            set.insert(Record::from_rdata(apex.clone(), ttl, rdata), 0);
        }
        set
    }

    /// The DS RRset a parent publishes for the zone at `apex`: one DS with
    /// `digest` for each key with the Secure Entry Point bit, or for every
    /// key if none has it.
    ///
    /// Refuses a digest type or key algorithm `policy` does not let this
    /// world create records with, as RFC 9905 forbids SHA-1 digests and
    /// algorithms 5 and 7.
    pub fn ds(
        &self,
        apex: &Name,
        ttl: u32,
        digest: DigestType,
        policy: &AlgorithmPolicy,
    ) -> Result<RecordSet, KeyError> {
        if !policy.delegates(digest.number()) {
            return Err(KeyError::DigestNotForDelegation(digest.number()));
        }
        let mut set = RecordSet::with_ttl(apex.clone(), RecordType::DS, ttl);
        for key in self.entry_keys() {
            let algorithm = u8::from(key.public_key().algorithm());
            if !policy.signs(algorithm) {
                return Err(KeyError::AlgorithmNotForSigning(algorithm));
            }
            let rdata = RData::DNSSEC(DNSSECRData::DS(ds(apex, &key, digest)));
            set.insert(Record::from_rdata(apex.clone(), ttl, rdata), 0);
        }
        Ok(set)
    }

    /// A trust anchor for the zone at `apex`: a SHA-256 DS for each key
    /// [`KeySet::ds`] would publish one for.
    pub fn anchor(&self, apex: &Name) -> TrustAnchor {
        TrustAnchor {
            owner: apex.clone(),
            ds: self
                .entry_keys()
                .map(|key| ds(apex, &key, DigestType::Sha256))
                .collect(),
        }
    }

    fn entry_keys(&self) -> impl Iterator<Item = DNSKEY> + '_ {
        let any_sep = self
            .keys
            .iter()
            .any(|key| KeyFlags(key.dnskey().flags()).secure_entry_point());
        self.keys
            .iter()
            .map(|key| key.dnskey())
            .filter(move |key| !any_sep || KeyFlags(key.flags()).secure_entry_point())
    }
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.keys.iter().map(|key| key_tag(&key.dnskey())))
            .finish()
    }
}

/// The DS record data for `key` at `owner` with `digest`: the digest of
/// the owner's lowercase wire form followed by the DNSKEY RDATA
/// (RFC 4034 §5.1.4).
pub fn ds(owner: &Name, key: &DNSKEY, digest: DigestType) -> DS {
    DS::new(
        key_tag(key),
        key.public_key().algorithm(),
        digest.hickory(),
        digest_of(owner, key, digest),
    )
}

/// The bytes a DS digest is computed over, hashed with `digest`.
pub(crate) fn digest_of(owner: &Name, key: &DNSKEY, digest: DigestType) -> Vec<u8> {
    let mut bytes = lowercase_wire(owner);
    bytes.extend_from_slice(&dnskey_rdata(key));
    digest.digest(&bytes)
}

/// The key tag of `key` (RFC 4034 Appendix B).
pub fn key_tag(key: &DNSKEY) -> u16 {
    let rdata = dnskey_rdata(key);
    // Appendix B.1: algorithm 1 keys use the modulus's low octets instead.
    if u8::from(key.public_key().algorithm()) == 1 {
        let n = rdata.len();
        return if n >= 3 {
            u16::from_be_bytes([rdata[n - 3], rdata[n - 2]])
        } else {
            0
        };
    }
    let mut ac: u32 = 0;
    for (i, octet) in rdata.iter().enumerate() {
        ac += if i & 1 == 0 {
            u32::from(*octet) << 8
        } else {
            u32::from(*octet)
        };
    }
    ac += (ac >> 16) & 0xffff;
    (ac & 0xffff) as u16
}

/// The DNSKEY RDATA on the wire: flags, protocol 3, algorithm, and the
/// public key (RFC 4034 §2.1).
fn dnskey_rdata(key: &DNSKEY) -> Vec<u8> {
    let public = key.public_key();
    let mut rdata = Vec::with_capacity(4 + public.public_bytes().len());
    rdata.extend_from_slice(&key.flags().to_be_bytes());
    rdata.push(3);
    rdata.push(u8::from(public.algorithm()));
    rdata.extend_from_slice(public.public_bytes());
    rdata
}

/// `name` on the wire, uncompressed and in lowercase (RFC 4034 §6.2).
fn lowercase_wire(name: &Name) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name.iter() {
        wire.push(label.len() as u8);
        wire.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    wire.push(0);
    wire
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{Seed, SeededEntropy};

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn generate(seed: u64, algorithm: Algorithm, flags: KeyFlags) -> ZoneKey {
        ZoneKey::generate(&SeededEntropy::new(Seed::from_u64(seed)), algorithm, flags)
    }

    #[test]
    fn root_key_tags_and_ds_match_the_published_anchors() {
        let anchors = hickory_proto::dnssec::TrustAnchors::default();
        let mut found = Vec::new();
        for index in 0..anchors.len() {
            let key = DNSKEY::with_flags(257, anchors.get(index).unwrap().clone());
            let tag = key_tag(&key);
            // hickory computes the same tag its own way.
            assert_eq!(tag, key.calculate_key_tag().unwrap());
            let ds = ds(&Name::root(), &key, DigestType::Sha256);
            found.push((tag, hex(ds.digest())));
        }
        found.sort();
        // https://data.iana.org/root-anchors/root-anchors.xml
        assert_eq!(
            found,
            [
                (
                    20326,
                    "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d".to_string()
                ),
                (
                    38696,
                    "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16".to_string()
                ),
            ]
        );
    }

    #[test]
    fn rfc_4034_example_key_tag() {
        // RFC 4034 §5.4: the DS for dskey.example.com has key tag 60485
        // and this SHA-1 digest.
        let public = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==";
        let bytes = base64(public);
        let key = DNSKEY::with_flags(
            256,
            PublicKeyBuf::new(bytes, hickory_proto::dnssec::Algorithm::from_u8(5)),
        );
        assert_eq!(key_tag(&key), 60485);
        let ds = ds(&name("dskey.example.com."), &key, DigestType::Sha1);
        assert_eq!(hex(ds.digest()), "2bb183af5f22588179a53b0a98631fad1a292118");
    }

    #[test]
    fn keys_round_trip_through_pkcs8() {
        for algorithm in [
            Algorithm::EcdsaP256Sha256,
            Algorithm::EcdsaP384Sha384,
            Algorithm::Ed25519,
        ] {
            let key = generate(3, algorithm, KeyFlags::ZSK);
            let back = ZoneKey::from_pkcs8(&key.to_pkcs8(), algorithm, KeyFlags::ZSK).unwrap();
            assert_eq!(back.dnskey(), key.dnskey());
            assert_eq!(
                back.sign(b"tbs"),
                key.sign(b"tbs"),
                "{algorithm:?} signs deterministically"
            );
        }
        let p256 = generate(3, Algorithm::EcdsaP256Sha256, KeyFlags::ZSK).to_pkcs8();
        assert_eq!(
            ZoneKey::from_pkcs8(&p256, Algorithm::Ed25519, KeyFlags::ZSK).unwrap_err(),
            KeyError::WrongAlgorithm(Algorithm::Ed25519)
        );
        assert_eq!(
            ZoneKey::from_pkcs8(&[0x30, 0], Algorithm::Ed25519, KeyFlags::ZSK).unwrap_err(),
            KeyError::Pkcs8
        );
    }

    #[test]
    fn ds_refuses_what_the_policy_forbids_and_points_at_entry_keys() {
        let ksk = generate(1, Algorithm::EcdsaP256Sha256, KeyFlags::KSK);
        let zsk = generate(2, Algorithm::EcdsaP256Sha256, KeyFlags::ZSK);
        let ksk_tag = key_tag(&ksk.dnskey());
        let keys = KeySet {
            keys: vec![Arc::new(ksk), Arc::new(zsk)],
        };
        let apex = name("example.");
        let policy = AlgorithmPolicy::iana();
        assert_eq!(
            keys.ds(&apex, 86400, DigestType::Sha1, &policy)
                .unwrap_err(),
            KeyError::DigestNotForDelegation(1)
        );
        let set = keys.ds(&apex, 86400, DigestType::Sha256, &policy).unwrap();
        let tags: Vec<u16> = set
            .records_without_rrsigs()
            .map(|record| match &record.data {
                RData::DNSSEC(DNSSECRData::DS(ds)) => ds.key_tag(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(tags, [ksk_tag]);
        assert_eq!(keys.anchor(&apex).ds.len(), 1);
        assert_eq!(keys.dnskey_rrset(&apex, 3600).records_count(), 2);

        let mut strict = AlgorithmPolicy::iana();
        strict.sign.remove(&13);
        assert_eq!(
            keys.ds(&apex, 86400, DigestType::Sha256, &strict)
                .unwrap_err(),
            KeyError::AlgorithmNotForSigning(13)
        );
    }

    #[test]
    fn flags() {
        assert!(KeyFlags::KSK.zone_key() && KeyFlags::KSK.secure_entry_point());
        assert!(KeyFlags::ZSK.zone_key() && !KeyFlags::ZSK.secure_entry_point());
        assert!(KeyFlags(0x0181).revoked());
        assert!(!KeyFlags(0x0001).zone_key());
    }

    pub(crate) fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn base64(text: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut count = 0;
        let mut out = Vec::new();
        for c in text.bytes().filter(|c| *c != b'=') {
            bits = bits << 6 | ALPHABET.iter().position(|a| *a == c).unwrap() as u32;
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
            }
        }
        out
    }
}
