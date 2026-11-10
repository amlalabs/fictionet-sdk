use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use p256::elliptic_curve::{sec1::ToSec1Point, zeroize::Zeroizing};
use p256::pkcs8::{DecodePrivateKey as _, EncodePublicKey as _};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rustls::ServerConfig;
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::ServerSessionSlots;
use rustls::sign::{Signer, SigningKey};
use rustls::time_provider::TimeProvider;
use rustls::{ConfigBuilder, NamedGroup, SignatureAlgorithm, SignatureScheme, WantsVersions};

use fictionet::stdlib::layer::Budget;
use fictionet::{Cx, Entropy};

use super::TlsBudget;

/// Starts a rustls server config whose time and randomness come from `fcx`.
///
/// rustls reads the current time, to check certificate validity and ticket
/// lifetimes, and draws random values for the handshake. A config built
/// with rustls's own builder takes both from the operating system. This
/// builder takes them from the world instead:
///
/// - **Time** is `start` plus the time since the run started, from `fcx`.
///   `start` is the world's date and time when the run started, which the
///   world takes from its arguments (see [No dates](fictionet::time#no-dates)).
///   So a world set in 2019 checks certificates against 2019.
/// - **Random values**, such as the server random, session IDs and ticket
///   identifiers, come from [`Cx::fill_random`](fictionet::Cx::fill_random).
///
/// Ephemeral keys and RSA-PSS salts also come from the run. ECDSA uses
/// deterministic RFC 6979 nonces, and Ed25519 signatures are deterministic.
/// With fixed certificates and world date, a closed lab using this provider
/// repeats its TLS records for the same seed and ordered inputs. A real run
/// uses the same random stream, but real peers determine handshake timing
/// and the order in which their inputs arrive.
///
/// The provider retains the run's entropy, including when a connection is
/// driven directly or moved between threads. Keep configs within their run:
/// both the clock and entropy retain the run's capabilities.
///
/// ```
/// # use fictionet::{Cx, Result, stdlib::services::tls};
/// # use rustls::pki_types::{CertificateDer, PrivateKeyDer};
/// # fn make(fcx: Cx, start: std::time::SystemTime, chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Result {
/// let config = tls::config_builder(&fcx, start)
///     .with_safe_default_protocol_versions()?
///     .with_no_client_auth()
///     .with_single_cert(chain, key)?;
/// # drop(config);
/// # Ok(())
/// # }
/// ```
pub fn config_builder(fcx: &Cx, start: SystemTime) -> ConfigBuilder<ServerConfig, WantsVersions> {
    let provider = crypto_provider(Arc::new(fcx.clone()));
    let clock = CxClock {
        fcx: fcx.clone(),
        start,
    };
    ServerConfig::builder_with_details(Arc::new(provider), Arc::new(clock))
}

/// How many sessions a server config's [`session_store`] keeps for
/// resumption, as rustls's own store does. The oldest goes first.
pub const SESSIONS: usize = 256;

/// The session store for a server config, made and paid for from `owner`
/// once, for the config's life: [`SESSIONS`] slots, into which a
/// connection's sessions are copied. A connection that stores, finds or
/// takes a session leaves nothing allocated once it is gone. Fails with
/// [`rustls::Error::BudgetExhausted`] if `owner` has no room.
pub fn session_store(owner: &Budget) -> Result<Arc<ServerSessionSlots>, rustls::Error> {
    ServerSessionSlots::with_budget(SESSIONS, TlsBudget::of(owner))
        .ok_or(rustls::Error::BudgetExhausted)
}

/// Starts a rustls client config using the same clock and randomness as [`config_builder`].
/// Keep the config within its run.
pub fn client_config_builder(
    fcx: &Cx,
    start: SystemTime,
) -> ConfigBuilder<rustls::ClientConfig, WantsVersions> {
    rustls::ClientConfig::builder_with_details(
        Arc::new(crypto_provider(Arc::new(fcx.clone()))),
        Arc::new(CxClock {
            fcx: fcx.clone(),
            start,
        }),
    )
}

/// The world's date: `start` plus the run's clock.
struct CxClock {
    fcx: Cx,
    start: SystemTime,
}

impl std::fmt::Debug for CxClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CxClock")
            .field("start", &self.start)
            .finish_non_exhaustive()
    }
}

impl TimeProvider for CxClock {
    fn current_time(&self) -> Option<UnixTime> {
        let now = self.start.checked_add(self.fcx.now().since_start())?;
        Some(UnixTime::since_unix_epoch(
            now.duration_since(UNIX_EPOCH).ok()?,
        ))
    }
}

/// rustls randomness backed by an owned run capability.
struct CxRandom(Arc<dyn Entropy>);

impl std::fmt::Debug for CxRandom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CxRandom")
    }
}

impl SecureRandom for CxRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        self.0.fill_random(buf);
        Ok(())
    }
}

/// Builds the run-aware TLS crypto provider.
///
/// Cipher suites, verification algorithms and their preference order are
/// ring's. Key exchange and signing retain the supplied entropy capability.
/// X25519, P-256 and P-384 secrets are zeroized when dropped. The provider
/// does not install a stateless ticketer; rustls's stateful cache remains
/// available. Custom resolvers and signers must honor the same contract.
///
/// The provider supplies cryptography, not the certificate clock. For a
/// client config, use `rustls::ClientConfig::builder_with_details` with a
/// `TimeProvider` derived from [`Cx::now`] and the world's date.
pub fn crypto_provider(entropy: Arc<dyn Entropy>) -> CryptoProvider {
    CryptoProvider {
        secure_random: Arc::new(CxRandom(entropy.clone())),
        kx_groups: vec![
            Arc::new(CxGroup(NamedGroup::X25519, CxRandom(entropy.clone()))),
            Arc::new(CxGroup(NamedGroup::secp256r1, CxRandom(entropy.clone()))),
            Arc::new(CxGroup(NamedGroup::secp384r1, CxRandom(entropy.clone()))),
        ],
        key_provider: Arc::new(CxKeyProvider {
            random: CxRandom(entropy),
        }),
        ..rustls::crypto::ring::default_provider()
    }
}

#[derive(Debug)]
struct CxGroup(NamedGroup, CxRandom);

impl SupportedKxGroup for CxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = match self.0 {
            NamedGroup::X25519 => {
                let mut bytes = Zeroizing::new([0; 32]);
                self.1.fill(bytes.as_mut())?;
                ExchangeSecret::X25519(x25519_dalek::StaticSecret::from(*bytes))
            }
            NamedGroup::secp256r1 => loop {
                let mut bytes = Zeroizing::new([0; 32]);
                self.1.fill(bytes.as_mut())?;
                if let Ok(secret) = p256::SecretKey::from_slice(bytes.as_ref()) {
                    break ExchangeSecret::P256(secret);
                }
            },
            NamedGroup::secp384r1 => loop {
                let mut bytes = Zeroizing::new([0; 48]);
                self.1.fill(bytes.as_mut())?;
                if let Ok(secret) = p384::SecretKey::from_slice(bytes.as_ref()) {
                    break ExchangeSecret::P384(secret);
                }
            },
            _ => unreachable!(),
        };
        let public = match &secret {
            ExchangeSecret::X25519(s) => x25519_dalek::PublicKey::from(s).as_bytes().to_vec(),
            ExchangeSecret::P256(s) => s.public_key().to_sec1_point(false).as_bytes().to_vec(),
            ExchangeSecret::P384(s) => s.public_key().to_sec1_point(false).as_bytes().to_vec(),
        };
        Ok(Box::new(Exchange {
            secret,
            public,
            group: self.0,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.0
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}

// Each primitive owns and zeroizes its secret on drop, including on failure.
enum ExchangeSecret {
    X25519(x25519_dalek::StaticSecret),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
}

struct Exchange {
    secret: ExchangeSecret,
    public: Vec<u8>,
    group: NamedGroup,
}

fn invalid_share() -> rustls::Error {
    rustls::PeerMisbehaved::InvalidKeyShare.into()
}

impl ActiveKeyExchange for Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        match &self.secret {
            ExchangeSecret::X25519(secret) => {
                let bytes: [u8; 32] = peer.try_into().map_err(|_| invalid_share())?;
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(bytes));
                if !shared.was_contributory() {
                    return Err(invalid_share());
                }
                Ok(SharedSecret::from(shared.as_bytes().as_slice()))
            }
            ExchangeSecret::P256(secret) => {
                if peer.len() != 65 || peer[0] != 4 {
                    return Err(invalid_share());
                }
                // PublicKey parsing rejects off-curve points and the identity.
                let public = p256::PublicKey::from_sec1_bytes(peer).map_err(|_| invalid_share())?;
                let shared =
                    p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
            }
            ExchangeSecret::P384(secret) => {
                if peer.len() != 97 || peer[0] != 4 {
                    return Err(invalid_share());
                }
                let public = p384::PublicKey::from_sec1_bytes(peer).map_err(|_| invalid_share())?;
                let shared =
                    p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
            }
        }
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        self.group
    }
}

#[derive(Debug)]
struct CxKeyProvider {
    random: CxRandom,
}

// Debug deliberately excludes private key material.
enum KeyMaterial {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Rsa(Box<rsa::RsaPrivateKey>),
}

struct RunSigningKey {
    entropy: Arc<dyn Entropy>,
    material: Arc<KeyMaterial>,
    public: Vec<u8>,
}

impl std::fmt::Debug for RunSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunSigningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

fn key_error(e: impl std::fmt::Display) -> rustls::Error {
    rustls::Error::General(format!("TLS private key: {e}"))
}

impl KeyProvider for CxKeyProvider {
    fn load_private_key(
        &self,
        der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        let rsa = match &der {
            PrivateKeyDer::Pkcs1(d) => {
                rsa::RsaPrivateKey::from_pkcs1_der(d.secret_pkcs1_der()).ok()
            }
            PrivateKeyDer::Pkcs8(d) => {
                rsa::RsaPrivateKey::from_pkcs8_der(d.secret_pkcs8_der()).ok()
            }
            _ => None,
        };
        if let Some(key) = rsa {
            // Retain ring's key size and encoding validation, without signing
            // or obtaining entropy from ring.
            match &der {
                PrivateKeyDer::Pkcs1(d) => {
                    ring::signature::RsaKeyPair::from_der(d.secret_pkcs1_der())
                }
                PrivateKeyDer::Pkcs8(d) => {
                    ring::signature::RsaKeyPair::from_pkcs8(d.secret_pkcs8_der())
                }
                _ => unreachable!(),
            }
            .map_err(key_error)?;
            key.validate().map_err(key_error)?;
            let public = key
                .to_public_key()
                .to_public_key_der()
                .map_err(key_error)?
                .as_bytes()
                .to_vec();
            return Ok(Arc::new(RunSigningKey {
                entropy: self.random.0.clone(),
                material: Arc::new(KeyMaterial::Rsa(Box::new(key))),
                public,
            }));
        }
        let p256 = match &der {
            PrivateKeyDer::Pkcs8(d) => p256::SecretKey::from_pkcs8_der(d.secret_pkcs8_der()).ok(),
            PrivateKeyDer::Sec1(d) => p256::SecretKey::from_sec1_der(d.secret_sec1_der()).ok(),
            _ => None,
        };
        if let Some(key) = p256 {
            let public = key
                .public_key()
                .to_public_key_der()
                .map_err(key_error)?
                .as_bytes()
                .to_vec();
            return Ok(Arc::new(RunSigningKey {
                entropy: self.random.0.clone(),
                material: Arc::new(KeyMaterial::P256(key.into())),
                public,
            }));
        }
        let p384 = match &der {
            PrivateKeyDer::Pkcs8(d) => p384::SecretKey::from_pkcs8_der(d.secret_pkcs8_der()).ok(),
            PrivateKeyDer::Sec1(d) => p384::SecretKey::from_sec1_der(d.secret_sec1_der()).ok(),
            _ => None,
        };
        if let Some(key) = p384 {
            let public = key
                .public_key()
                .to_public_key_der()
                .map_err(key_error)?
                .as_bytes()
                .to_vec();
            return Ok(Arc::new(RunSigningKey {
                entropy: self.random.0.clone(),
                material: Arc::new(KeyMaterial::P384(key.into())),
                public,
            }));
        }
        if let PrivateKeyDer::Pkcs8(d) = &der {
            // Ed25519 parsing and signing in ring take no RNG.
            return rustls::crypto::ring::sign::any_eddsa_type(d);
        }
        Err(key_error("unsupported encoding or algorithm"))
    }
}

const RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

impl SigningKey for RunSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let supported: &[SignatureScheme] = match &*self.material {
            KeyMaterial::P256(_) => &[SignatureScheme::ECDSA_NISTP256_SHA256],
            KeyMaterial::P384(_) => &[SignatureScheme::ECDSA_NISTP384_SHA384],
            KeyMaterial::Rsa(_) => RSA_SCHEMES,
        };
        let scheme = *supported.iter().find(|s| offered.contains(s))?;
        Some(Box::new(RunSigner {
            entropy: self.entropy.clone(),
            material: self.material.clone(),
            scheme,
        }))
    }
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.public.as_slice().into())
    }
    fn algorithm(&self) -> SignatureAlgorithm {
        match &*self.material {
            KeyMaterial::P256(_) | KeyMaterial::P384(_) => SignatureAlgorithm::ECDSA,
            KeyMaterial::Rsa(_) => SignatureAlgorithm::RSA,
        }
    }
}

struct RunSigner {
    entropy: Arc<dyn Entropy>,
    material: Arc<KeyMaterial>,
    scheme: SignatureScheme,
}

impl std::fmt::Debug for RunSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

struct CxRng(Arc<dyn Entropy>);
impl rsa::rand_core::CryptoRng for CxRng {}
impl rsa::rand_core::RngCore for CxRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.0.fill_random(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        self.0.random_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_random(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl Signer for RunSigner {
    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        match &*self.material {
            KeyMaterial::P256(key) => {
                let signature: p256::ecdsa::Signature = key
                    .sign_prehash(ring::digest::digest(&ring::digest::SHA256, message).as_ref())
                    .map_err(key_error)?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            KeyMaterial::P384(key) => {
                let signature: p384::ecdsa::Signature = key
                    .sign_prehash(ring::digest::digest(&ring::digest::SHA384, message).as_ref())
                    .map_err(key_error)?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            KeyMaterial::Rsa(key) => {
                let mut rng = CxRng(self.entropy.clone());
                let hash = match self.scheme {
                    SignatureScheme::RSA_PSS_SHA256 | SignatureScheme::RSA_PKCS1_SHA256 => {
                        &ring::digest::SHA256
                    }
                    SignatureScheme::RSA_PSS_SHA384 | SignatureScheme::RSA_PKCS1_SHA384 => {
                        &ring::digest::SHA384
                    }
                    SignatureScheme::RSA_PSS_SHA512 | SignatureScheme::RSA_PKCS1_SHA512 => {
                        &ring::digest::SHA512
                    }
                    _ => unreachable!(),
                };
                let digest = ring::digest::digest(hash, message);
                // PSS uses digest-sized salts and RSA blinding draws from Cx too.
                match self.scheme {
                    SignatureScheme::RSA_PSS_SHA256 => key.sign_with_rng(
                        &mut rng,
                        rsa::Pss::new_blinded::<rsa::sha2::Sha256>(),
                        digest.as_ref(),
                    ),
                    SignatureScheme::RSA_PSS_SHA384 => key.sign_with_rng(
                        &mut rng,
                        rsa::Pss::new_blinded::<rsa::sha2::Sha384>(),
                        digest.as_ref(),
                    ),
                    SignatureScheme::RSA_PSS_SHA512 => key.sign_with_rng(
                        &mut rng,
                        rsa::Pss::new_blinded::<rsa::sha2::Sha512>(),
                        digest.as_ref(),
                    ),
                    SignatureScheme::RSA_PKCS1_SHA256 => key.sign_with_rng(
                        &mut rng,
                        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                        digest.as_ref(),
                    ),
                    SignatureScheme::RSA_PKCS1_SHA384 => key.sign_with_rng(
                        &mut rng,
                        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha384>(),
                        digest.as_ref(),
                    ),
                    SignatureScheme::RSA_PKCS1_SHA512 => key.sign_with_rng(
                        &mut rng,
                        rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha512>(),
                        digest.as_ref(),
                    ),
                    _ => unreachable!(),
                }
                .map_err(key_error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn randomness_preserves_partial_fills() {
        use fictionet::{Entropy, SeededEntropy};
        use rustls::crypto::SecureRandom;
        let mut byte = [0; 1];
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(42),
            |fcx| async move {
                let oracle = SeededEntropy::new(fictionet::Seed::from_u64(42));
                let mut expected = [0; 1];
                oracle.fill_random(&mut expected);
                super::CxRandom(std::sync::Arc::new(fcx.clone()))
                    .fill(&mut byte)
                    .unwrap();
                assert_eq!(byte, expected);
                assert_eq!(fcx.random_u64(), oracle.random_u64());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn crypto_provider_draws_follow_the_run_seed() {
        use fictionet::{Seed, block_on, lab};
        use rustls::pki_types::PrivateKeyDer;
        use std::sync::{Arc, Mutex};

        fn draw(provider: rustls::crypto::CryptoProvider) -> Vec<Vec<u8>> {
            let mut bytes = vec![0; 17];
            provider.secure_random.fill(&mut bytes).unwrap();
            let mut result = vec![bytes];
            for group in provider.kx_groups {
                let first = group.start().unwrap();
                let second = group.start().unwrap();
                let a = first.pub_key().to_vec();
                let b = second.pub_key().to_vec();
                let shared = first.complete(&b).unwrap();
                assert_eq!(
                    shared.secret_bytes(),
                    second.complete(&a).unwrap().secret_bytes()
                );
                result.extend([a, b, shared.secret_bytes().to_vec()]);
            }
            let key = provider
                .key_provider
                .load_private_key(
                    PrivateKeyDer::try_from(
                        include_bytes!("../../../../tests/it/fixtures/tls/rsa.key.der").to_vec(),
                    )
                    .unwrap(),
                )
                .unwrap();
            result.push(
                key.choose_scheme(&[rustls::SignatureScheme::RSA_PSS_SHA256])
                    .unwrap()
                    .sign(b"seeded TLS")
                    .unwrap(),
            );
            result
        }

        let exercise = |seed| {
            let result = Arc::new(Mutex::new(Vec::new()));
            let output = result.clone();
            block_on(lab(Seed::from_u64(seed), move |cx| async move {
                *output.lock().unwrap() = draw(super::crypto_provider(Arc::new(cx.clone())));
                Ok(())
            }))
            .unwrap();
            Arc::try_unwrap(result).unwrap().into_inner().unwrap()
        };
        assert_eq!(exercise(91), exercise(91));
        assert_ne!(exercise(91), exercise(92));
    }
}
