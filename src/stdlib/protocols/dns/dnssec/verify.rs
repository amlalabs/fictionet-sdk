//! Checking one signature with one public key.
//!
//! The validator asks a [`Verify`] whether a DNSKEY made a signature over
//! some bytes, and nothing else. A verifier sees no zone, no signer, and no
//! source of records, so swapping how keys are held or records are served
//! cannot change what the validator accepts.

use super::rdata::DNSKEY;
use hickory_proto::dnssec::PublicKey;

/// Checks a signature against a DNSKEY.
pub trait Verify {
    /// Whether `signature` is `key`'s signature over `tbs`, the
    /// to-be-signed bytes of RFC 4034 §3.1.8.1.
    fn verify(&self, key: &DNSKEY, tbs: &[u8], signature: &[u8]) -> bool;
}

/// The verifier hickory builds on ring. It checks algorithms 5, 7, 8, 10,
/// 13, 14, and 15 and rejects every other algorithm and any RSA modulus
/// shorter than 1024 bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ring;

impl Verify for Ring {
    fn verify(&self, key: &DNSKEY, tbs: &[u8], signature: &[u8]) -> bool {
        let public = key.public_key();
        // hickory asserts in debug builds that the algorithm is one it
        // knows, so an unknown one is turned away first.
        public.algorithm().is_supported() && public.verify(tbs, signature).is_ok()
    }
}
