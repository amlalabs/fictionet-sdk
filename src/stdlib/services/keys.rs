//! Private keys made from the run's seeded randomness.
//!
//! [`Key::generate`] draws every byte a key needs from an [`Entropy`], so a
//! seeded run makes the same key every time. Pass a [`Cx`](fictionet::Cx)
//! to use the run's stream. The certificate authorities in
//! [`ca`](super::ca) sign with these keys.
//!
//! Keys go out and come back as PKCS#8 DER. RSA generation is slow, so a
//! world that needs the same RSA key on every run can store it once with
//! [`Key::to_pkcs8`] and read it back with [`Key::from_pkcs8`].

use fictionet::{Entropy, Error};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ring::signature::KeyPair;

/// A key's algorithm and size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// A P-256 key. Certificates it signs use ECDSA-SHA256.
    P256,
    /// A P-384 key. Certificates it signs use ECDSA-SHA384.
    P384,
    /// An RSA 2048-bit key. Certificates it signs use RSASSA-PKCS1-v1_5
    /// with SHA-256.
    Rsa2048,
    /// An Ed25519 key (RFC 8032).
    Ed25519,
}

/// A private key.
pub enum Key {
    /// A P-256 ECDSA key.
    P256(p256::ecdsa::SigningKey),
    /// A P-384 ECDSA key.
    P384(p384::ecdsa::SigningKey),
    /// An RSA key.
    Rsa(Box<rsa::RsaPrivateKey>),
    /// An Ed25519 key.
    Ed25519(Ed25519),
}

impl Key {
    /// Generates a key of `kind` from `entropy`.
    pub fn generate(entropy: &dyn Entropy, kind: KeyKind) -> Key {
        match kind {
            KeyKind::P256 => loop {
                let mut bytes = [0; 32];
                entropy.fill_random(&mut bytes);
                if let Ok(key) = p256::ecdsa::SigningKey::from_bytes((&bytes).into()) {
                    break Key::P256(key);
                }
            },
            KeyKind::P384 => loop {
                let mut bytes = [0; 48];
                entropy.fill_random(&mut bytes);
                if let Ok(key) = p384::ecdsa::SigningKey::from_bytes((&bytes).into()) {
                    break Key::P384(key);
                }
            },
            KeyKind::Rsa2048 => Key::Rsa(Box::new(
                rsa::RsaPrivateKey::new(&mut SeededRng(entropy), 2048)
                    .expect("RSA 2048 key generation"),
            )),
            KeyKind::Ed25519 => {
                let mut seed = [0; 32];
                entropy.fill_random(&mut seed);
                Key::Ed25519(Ed25519::from_seed(seed))
            }
        }
    }

    /// The key as PKCS#8 DER. An Ed25519 key is written in the version 1
    /// form of RFC 8410, section 7, which holds only the seed.
    pub fn to_pkcs8(&self) -> Vec<u8> {
        match self {
            Key::P256(key) => key
                .to_pkcs8_der()
                .expect("a P-256 key encodes")
                .as_bytes()
                .to_vec(),
            Key::P384(key) => key
                .to_pkcs8_der()
                .expect("a P-384 key encodes")
                .as_bytes()
                .to_vec(),
            Key::Rsa(key) => rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(key.as_ref())
                .expect("an RSA key encodes")
                .as_bytes()
                .to_vec(),
            Key::Ed25519(key) => key.to_pkcs8(),
        }
    }

    /// Reads a PKCS#8 DER P-256, P-384, Ed25519, or RSA key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Key, Error> {
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Key::P256(key));
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Key::P384(key));
        }
        if let Some(key) = Ed25519::from_pkcs8(der) {
            return Ok(Key::Ed25519(key));
        }
        Ok(Key::Rsa(Box::new(
            <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_der(der)?,
        )))
    }
}

/// An Ed25519 key, kept as its 32-byte seed (RFC 8032, section 5.1.5)
/// with the key pair ring derives from it.
pub struct Ed25519 {
    seed: [u8; 32],
    pair: ring::signature::Ed25519KeyPair,
}

/// The fixed start of a version 1 Ed25519 PKCS#8 key (RFC 8410, section 7):
/// the sequence, version 0, the algorithm 1.3.101.112, and the octet string
/// that wraps the 32-byte seed.
const ED25519_PKCS8_V1: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

impl Ed25519 {
    /// The key whose private seed is `seed`.
    pub fn from_seed(seed: [u8; 32]) -> Ed25519 {
        let pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .expect("every 32-byte seed is an Ed25519 key");
        Ed25519 { seed, pair }
    }

    /// The private seed.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> &[u8] {
        self.pair.public_key().as_ref()
    }

    /// The 64-byte signature of `message`. Ed25519 signing is
    /// deterministic, so it draws no randomness.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }

    fn to_pkcs8(&self) -> Vec<u8> {
        let mut der = ED25519_PKCS8_V1.to_vec();
        der.extend_from_slice(&self.seed);
        der
    }

    /// Reads a version 1 or version 2 Ed25519 PKCS#8 key (RFC 8410,
    /// section 7). ring checks the DER structure and, in version 2, that
    /// the public key belongs to the seed. Both versions are shorter than
    /// 128 octets, so DER fixes the seed at the same offset in each.
    fn from_pkcs8(der: &[u8]) -> Option<Ed25519> {
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).ok()?;
        let key = Ed25519::from_seed(der.get(16..48)?.try_into().ok()?);
        (key.public_key() == pair.public_key().as_ref()).then_some(key)
    }
}

/// A random source for RSA key generation that reads from an [`Entropy`],
/// so a seeded run makes the same key every time, as the elliptic curve
/// paths do with `fill_random`.
struct SeededRng<'a>(&'a dyn Entropy);

impl rsa::rand_core::RngCore for SeededRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_random(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for SeededRng<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::{Seed, SeededEntropy};

    fn generate(seed: u64, kind: KeyKind) -> Key {
        Key::generate(&SeededEntropy::new(Seed::from_u64(seed)), kind)
    }

    #[test]
    fn generation_is_repeatable_and_round_trips_through_pkcs8() {
        for kind in [
            KeyKind::P256,
            KeyKind::P384,
            KeyKind::Rsa2048,
            KeyKind::Ed25519,
        ] {
            let der = generate(5, kind).to_pkcs8();
            assert_eq!(generate(5, kind).to_pkcs8(), der, "{kind:?}");
            assert_ne!(generate(6, kind).to_pkcs8(), der, "{kind:?}");
            let back = Key::from_pkcs8(&der).unwrap();
            assert_eq!(back.to_pkcs8(), der, "{kind:?}");
            let read_kind = match back {
                Key::P256(_) => KeyKind::P256,
                Key::P384(_) => KeyKind::P384,
                Key::Rsa(_) => KeyKind::Rsa2048,
                Key::Ed25519(_) => KeyKind::Ed25519,
            };
            assert_eq!(read_kind, kind);
        }
    }

    #[test]
    fn ed25519_uses_the_next_32_bytes_as_its_seed() {
        let entropy = SeededEntropy::new(Seed::from_u64(9));
        let Key::Ed25519(key) = Key::generate(&entropy, KeyKind::Ed25519) else {
            panic!("an Ed25519 key");
        };
        let mut seed = [0; 32];
        SeededEntropy::new(Seed::from_u64(9)).fill_random(&mut seed);
        assert_eq!(key.seed(), &seed);
        assert_eq!(key.public_key().len(), 32);

        let message = b"signed by a seeded key";
        let signature = key.sign(message);
        assert_eq!(signature.len(), 64);
        assert_eq!(key.sign(message), signature);
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key.public_key())
            .verify(message, &signature)
            .unwrap();
    }

    #[test]
    fn ed25519_reads_rings_version_2_pkcs8() {
        let Key::Ed25519(key) = generate(11, KeyKind::Ed25519) else {
            panic!("an Ed25519 key");
        };
        // RFC 8410, section 10.3: version 1 with the public key in an
        // explicit [1] bit string, the form ring writes.
        let mut v2 = vec![
            0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        v2.extend_from_slice(key.seed());
        v2.extend_from_slice(&[0xa1, 0x23, 0x03, 0x21, 0x00]);
        v2.extend_from_slice(key.public_key());
        let Key::Ed25519(back) = Key::from_pkcs8(&v2).unwrap() else {
            panic!("an Ed25519 key");
        };
        assert_eq!(back.seed(), key.seed());

        let Key::Ed25519(other) = generate(12, KeyKind::Ed25519) else {
            panic!("an Ed25519 key");
        };
        let at = v2.len() - 32;
        v2[at..].copy_from_slice(other.public_key());
        assert!(Key::from_pkcs8(&v2).is_err());
    }

    #[test]
    fn garbage_is_not_a_key() {
        assert!(Key::from_pkcs8(&[]).is_err());
        assert!(Key::from_pkcs8(&[0x30, 0x00]).is_err());
        let mut short = ED25519_PKCS8_V1.to_vec();
        short.extend_from_slice(&[7; 31]);
        assert!(Key::from_pkcs8(&short).is_err());
    }
}
