//! The DNSSEC algorithms and DS digest types this code can create
//! records with.
//!
//! These enums name what the code implements, not what a world allows. A
//! world's choice of which registry numbers to sign, delegate, and accept
//! with is an [`AlgorithmPolicy`](super::AlgorithmPolicy), which keeps them
//! as plain registry numbers so a new registry entry needs no code change.

use hickory_proto::dnssec as hickory;

/// A DNSKEY algorithm a [`ZoneKey`](super::ZoneKey) can sign with, from the
/// IANA "DNS Security Algorithm Numbers" registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Algorithm {
    /// RSA/SHA-256, number 8 (RFC 5702). The real root zone signs with it.
    RsaSha256,
    /// RSA/SHA-512, number 10 (RFC 5702).
    RsaSha512,
    /// ECDSA with curve P-256 and SHA-256, number 13 (RFC 6605).
    EcdsaP256Sha256,
    /// ECDSA with curve P-384 and SHA-384, number 14 (RFC 6605).
    EcdsaP384Sha384,
    /// Ed25519, number 15 (RFC 8080).
    Ed25519,
}

impl Algorithm {
    /// Every algorithm, in registry order.
    pub const ALL: [Algorithm; 5] = [
        Algorithm::RsaSha256,
        Algorithm::RsaSha512,
        Algorithm::EcdsaP256Sha256,
        Algorithm::EcdsaP384Sha384,
        Algorithm::Ed25519,
    ];

    /// The registry number.
    pub const fn number(self) -> u8 {
        match self {
            Algorithm::RsaSha256 => 8,
            Algorithm::RsaSha512 => 10,
            Algorithm::EcdsaP256Sha256 => 13,
            Algorithm::EcdsaP384Sha384 => 14,
            Algorithm::Ed25519 => 15,
        }
    }

    /// The algorithm with registry number `number`, if this code can sign
    /// with it.
    pub fn from_number(number: u8) -> Option<Algorithm> {
        Algorithm::ALL.into_iter().find(|a| a.number() == number)
    }

    /// hickory's name for the same registry number, which its DNSKEY and
    /// RRSIG types carry.
    pub(crate) fn hickory(self) -> hickory::Algorithm {
        hickory::Algorithm::from_u8(self.number())
    }
}

/// A DS digest type, from the IANA "Digest Algorithms" registry for DS
/// records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DigestType {
    /// SHA-1, number 1 (RFC 4034 §5.1.4). RFC 9905 forbids it for new
    /// delegations; validators still accept it.
    Sha1,
    /// SHA-256, number 2 (RFC 4509).
    Sha256,
    /// SHA-384, number 4 (RFC 6605).
    Sha384,
}

impl DigestType {
    /// Every digest type, in registry order.
    pub const ALL: [DigestType; 3] = [DigestType::Sha1, DigestType::Sha256, DigestType::Sha384];

    /// The registry number.
    pub const fn number(self) -> u8 {
        match self {
            DigestType::Sha1 => 1,
            DigestType::Sha256 => 2,
            DigestType::Sha384 => 4,
        }
    }

    /// The digest type with registry number `number`, if this code can
    /// compute it.
    pub fn from_number(number: u8) -> Option<DigestType> {
        DigestType::ALL.into_iter().find(|d| d.number() == number)
    }

    /// The digest of `bytes`.
    pub fn digest(self, bytes: &[u8]) -> Vec<u8> {
        let algorithm = match self {
            DigestType::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            DigestType::Sha256 => &ring::digest::SHA256,
            DigestType::Sha384 => &ring::digest::SHA384,
        };
        ring::digest::digest(algorithm, bytes).as_ref().to_vec()
    }

    pub(crate) fn hickory(self) -> hickory::DigestType {
        hickory::DigestType::from(self.number())
    }
}
