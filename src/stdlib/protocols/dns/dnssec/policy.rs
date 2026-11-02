//! Which DNSSEC algorithms and digest types a world signs, delegates, and
//! validates with.
//!
//! RFC 9904 moved the algorithm recommendations out of RFC text into
//! columns of the IANA registries, and RFC 9905 set the columns for SHA-1:
//! algorithms 5 and 7 and digest type 1 must not be used to create
//! records, and validator operators must treat algorithms 5 and 7 as
//! unsupported. [`AlgorithmPolicy::iana`] is those columns, read from the
//! registries on 2026-11-01.
//!
//! The policy is a value of its own, apart from what a verifier can check,
//! so a world can accept less (or more) than the registry without touching
//! the validator.

use std::collections::BTreeSet;

use super::DigestType;
use super::rdata::DS;

/// The registry numbers a world signs, delegates, and validates with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlgorithmPolicy {
    /// DNSKEY algorithms whose signatures may make an answer Secure. A
    /// zone whose DS records name only other algorithms is Insecure, as
    /// for any algorithm a validator does not support (RFC 4035 §5.2,
    /// RFC 9905 §2).
    pub validate: BTreeSet<u8>,
    /// DS digest types that may link a parent zone to a child. A zone
    /// whose DS records use only other digest types is Insecure
    /// (RFC 4035 §5.2).
    pub digests: BTreeSet<u8>,
    /// DNSKEY algorithms this world may create DNSKEY and RRSIG records
    /// with.
    pub sign: BTreeSet<u8>,
    /// DS digest types this world may create DS records with.
    pub delegate: BTreeSet<u8>,
    /// NSEC3 iteration counts above this make a denial Insecure, with EDE
    /// 27 (RFC 9276 §3.2).
    pub max_nsec3_iterations: u16,
}

impl AlgorithmPolicy {
    /// The IANA registry columns as RFC 9904 and RFC 9905 set them.
    ///
    /// Validation accepts every algorithm the registry marks MUST or
    /// RECOMMENDED for validation that a [`Ring`](super::Ring) verifier
    /// can check: 8, 10, 13, 14, and 15. Algorithms 5 and 7 are left out,
    /// since RFC 9905 §2 has operators treat them as unsupported, and 16
    /// (Ed448) is left out because ring cannot verify it. Digests 1, 2,
    /// and 4 are RECOMMENDED for validation. Signing uses the algorithms
    /// marked RECOMMENDED or MAY for signing (8, 13, 14, and 15; 10 is NOT
    /// RECOMMENDED), and delegation the digests marked RECOMMENDED or MAY
    /// for delegation (2 and 4; 1 is MUST NOT).
    ///
    /// The registry says nothing about NSEC3 iterations. The limit is 100,
    /// the count RFC 9276 Appendix A found interoperable as the point where
    /// a validator treats a zone as Insecure.
    pub fn iana() -> AlgorithmPolicy {
        AlgorithmPolicy {
            validate: BTreeSet::from([8, 10, 13, 14, 15]),
            digests: BTreeSet::from([1, 2, 4]),
            sign: BTreeSet::from([8, 13, 14, 15]),
            delegate: BTreeSet::from([2, 4]),
            max_nsec3_iterations: 100,
        }
    }

    /// Whether signatures by DNSKEY algorithm `algorithm` may make an
    /// answer Secure.
    pub fn validates(&self, algorithm: u8) -> bool {
        self.validate.contains(&algorithm)
    }

    /// Whether DS digest type `digest` may link a parent to a child.
    pub fn accepts_digest(&self, digest: u8) -> bool {
        self.digests.contains(&digest)
    }

    /// Whether this world may sign with DNSKEY algorithm `algorithm`.
    pub fn signs(&self, algorithm: u8) -> bool {
        self.sign.contains(&algorithm)
    }

    /// Whether this world may create DS records with digest type `digest`.
    pub fn delegates(&self, digest: u8) -> bool {
        self.delegate.contains(&digest)
    }

    /// The DS records among `records` a validator uses to select a child's
    /// keys, each with its digest type: those whose algorithm and digest
    /// type the policy accepts, without the SHA-1 ones when a stronger
    /// digest is among them (RFC 4509 §3).
    pub fn usable_ds<'a>(
        &self,
        records: impl IntoIterator<Item = &'a DS>,
    ) -> Vec<(&'a DS, DigestType)> {
        let mut usable: Vec<(&DS, DigestType)> = records
            .into_iter()
            .filter(|ds| self.validates(u8::from(ds.algorithm())))
            .filter(|ds| self.accepts_digest(u8::from(ds.digest_type())))
            .filter_map(|ds| Some((ds, DigestType::from_number(u8::from(ds.digest_type()))?)))
            .collect();
        if usable.iter().any(|(_, digest)| *digest != DigestType::Sha1) {
            usable.retain(|(_, digest)| *digest != DigestType::Sha1);
        }
        usable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iana_follows_rfc_9904_and_rfc_9905() {
        let policy = AlgorithmPolicy::iana();
        for algorithm in [8, 10, 13, 14, 15] {
            assert!(policy.validates(algorithm), "{algorithm}");
        }
        for algorithm in [1, 3, 5, 6, 7, 12, 16] {
            assert!(!policy.validates(algorithm), "{algorithm}");
        }
        assert!(policy.accepts_digest(1));
        assert!(!policy.delegates(1));
        assert!(policy.delegates(2) && policy.delegates(4));
        assert!(!policy.signs(10) && !policy.signs(5) && !policy.signs(7));
        assert!(policy.signs(8) && policy.signs(13));
    }
}
