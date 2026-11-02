//! DNSSEC at the level of records: keys, signatures, trust anchors, denial
//! proofs, and the validator.
//!
//! Keys, DNSKEY and DS sets, RRSIGs, NSEC, and NSEC3 are records. A
//! [`ZoneKey`] signs an RRset into an RRSIG with [`sign`], deterministically,
//! so a seeded run makes the same signed zone every time. The validator,
//! [`validate_rrset`] and [`validate_denial`], is a function of records,
//! [`Anchors`], an [`AlgorithmPolicy`], a time, and a [`Verify`]. Nothing
//! that signs or serves records is among its inputs, so neither can change
//! what it accepts.
//!
//! DS digests, key tags, NSEC3 hashes, and signatures here are DNSSEC's own
//! operations on DNS records.
//!
//! hickory's record types for DNSSEC are re-exported: [`rdata`] holds
//! DNSKEY, DS, RRSIG, NSEC, and NSEC3. hickory's own signer draws from the
//! system's random source, so it is not used; its verifier is, through
//! [`Ring`].
//!
//! | Item | Standard |
//! | --- | --- |
//! | [`Algorithm`], [`DigestType`] | RFC 5702, RFC 6605, RFC 8080, RFC 4509 |
//! | [`AlgorithmPolicy`] | RFC 9904, RFC 9905, RFC 9276 §3.2 |
//! | [`ZoneKey`], [`KeySet`], [`key_tag`], [`ds`] | RFC 4034 §2, §5, Appendix B; RFC 3110 |
//! | [`sign`], [`Window`] | RFC 4034 §3, RFC 4035 §2.2 |
//! | [`Ring`] | RFC 4034 §3.1.8.1 |
//! | [`TrustAnchor`], [`Anchors`] | RFC 4035 §4.3, IANA root anchors |
//! | [`proof`] | RFC 4035 §5.4, RFC 5155 §8, RFC 6840 §4.1 |
//! | [`validate_rrset`], [`validate_denial`] | RFC 4035 §5, RFC 6840 §5, RFC 8914 |

pub use hickory_proto::dnssec::{Nsec3HashAlgorithm, PublicKey, PublicKeyBuf, TBS, rdata};

mod algorithm;
mod anchor;
mod keys;
mod policy;
pub mod proof;
mod sign;
mod validate;
mod verify;

pub use algorithm::{Algorithm, DigestType};
pub use anchor::{Anchors, TrustAnchor};
pub use keys::{KeyError, KeyFlags, KeySet, Sign, ZoneKey, ds, key_tag};
pub use policy::{AlgorithmPolicy, Treatment};
pub use proof::Proof;
pub use sign::{Window, sign, signed_data};
pub use validate::{
    Chain, Fetched, Insecure, Link, ValidatedDenial, Validation, validate_denial, validate_rrset,
};
pub use verify::{Ring, Verify};
