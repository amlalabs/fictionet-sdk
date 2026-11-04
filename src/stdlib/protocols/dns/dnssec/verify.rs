//! Checking one signature with one public key.
//!
//! The validator asks a [`Verify`] whether a DNSKEY made a signature over
//! some bytes, and nothing else. A verifier sees no zone, no signer, and no
//! source of records, so swapping how keys are held or records are served
//! cannot change what the validator accepts.

use super::rdata::DNSKEY;
use hickory_proto::dnssec::{Algorithm, PublicKey, PublicKeyBuf};
use rsa::sha2::{Digest, Sha256};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};

/// Checks a signature against a DNSKEY.
pub trait Verify {
    /// Whether `signature` is `key`'s signature over `tbs`, the
    /// to-be-signed bytes of RFC 4034 §3.1.8.1.
    fn verify(&self, key: &DNSKEY, tbs: &[u8], signature: &[u8]) -> bool;
}

/// The verifier hickory builds on ring. It checks algorithms 5, 7, 8, 10,
/// 13, 14, and 15 and rejects every other algorithm. ring takes RSA
/// moduli from 1024 bits; an RSA/SHA-256 modulus of 512 to 1023 bits,
/// which RFC 5702 §2 allows and [`ZoneKey`](super::ZoneKey) signs with,
/// is checked with the `rsa` crate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ring;

impl Verify for Ring {
    fn verify(&self, key: &DNSKEY, tbs: &[u8], signature: &[u8]) -> bool {
        let public = key.public_key();
        // hickory asserts in debug builds that the algorithm is one it
        // knows, so an unknown one is turned away first.
        if !public.algorithm().is_supported() {
            return false;
        }
        match short_rsa_sha256(public) {
            // RFC 5702 §3: RSASSA-PKCS1-v1_5 over the SHA-256 digest.
            Some(rsa) => rsa
                .verify(
                    Pkcs1v15Sign::new::<Sha256>(),
                    &Sha256::digest(tbs),
                    signature,
                )
                .is_ok(),
            None => public.verify(tbs, signature).is_ok(),
        }
    }
}

/// `public` as an RSA key, when it is an RSA/SHA-256 key whose modulus is
/// 512 to 1023 bits long, read as RFC 3110 §2 writes it: the exponent's
/// length in one octet, or a zero octet and two more, then the exponent
/// and the modulus.
fn short_rsa_sha256(public: &PublicKeyBuf) -> Option<RsaPublicKey> {
    if public.algorithm() != Algorithm::RSASHA256 {
        return None;
    }
    let (&first, rest) = public.public_bytes().split_first()?;
    let (length, rest) = match first {
        0 => {
            let (length, rest) = rest.split_first_chunk::<2>()?;
            (usize::from(u16::from_be_bytes(*length)), rest)
        }
        length => (usize::from(length), rest),
    };
    if rest.len() < length {
        return None;
    }
    let (exponent, modulus) = rest.split_at(length);
    let modulus = BigUint::from_bytes_be(modulus);
    if !(512..1024).contains(&modulus.bits()) {
        return None;
    }
    RsaPublicKey::new(modulus, BigUint::from_bytes_be(exponent)).ok()
}
