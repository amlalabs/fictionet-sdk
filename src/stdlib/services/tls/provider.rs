use std::cell::RefCell;
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
use rustls::sign::{Signer, SigningKey};
use rustls::time_provider::TimeProvider;
use rustls::{ConfigBuilder, NamedGroup, SignatureAlgorithm, SignatureScheme, WantsVersions};

use fictionet::Cx;

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
/// Random values are drawn while [`server`](super::server),
/// [`ClientHello::finish`](super::ClientHello::finish) or a
/// [`TlsConnection`](super::TlsConnection) is working, and come from the `Cx`
/// passed to that call.
/// Code driving rustls directly must bind a `Cx` with [`with_context`];
/// otherwise random draws fail.
///
/// Continue as with `ServerConfig::builder()`. Key loading does not draw
/// randomness. Keep configs within their run because the clock holds `fcx`:
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
    let provider = crypto_provider();
    let clock = CxClock {
        fcx: fcx.clone(),
        start,
    };
    ServerConfig::builder_with_details(Arc::new(provider), Arc::new(clock))
}

/// Starts a rustls client config using the same clock and randomness as [`config_builder`].
/// Keep the config within its run and bind direct rustls calls with [`with_context`].
pub fn client_config_builder(
    fcx: &Cx,
    start: SystemTime,
) -> ConfigBuilder<rustls::ClientConfig, WantsVersions> {
    rustls::ClientConfig::builder_with_details(
        Arc::new(crypto_provider()),
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

thread_local! {
    /// The `Cx` of the TLS work running on this thread now, if any.
    static CURRENT: RefCell<Option<Cx>> = const { RefCell::new(None) };
}

/// Runs synchronous TLS work with `fcx` as its source of randomness.
///
/// Bind each call that constructs or drives a rustls connection using
/// [`crypto_provider`]. The binding lasts only until `f` returns, including
/// during unwinding. Nested calls restore the previous context. Do not
/// return a future expecting the binding to remain active when it is polled.
pub fn with_context<T>(fcx: &Cx, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<Cx>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            CURRENT.with(|c| *c.borrow_mut() = previous);
        }
    }
    let previous = CURRENT.with(|c| c.borrow_mut().replace(fcx.clone()));
    let _restore = Restore(previous);
    f()
}

/// rustls's `SecureRandom`, from the `Cx` of the TLS work that draws it.
///
/// rustls keeps it as a `&'static`, so it cannot hold a `Cx` itself: it
/// reads the one [`with_context`] set for this thread.
#[derive(Debug)]
struct CxRandom;

impl SecureRandom for CxRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        CURRENT.with(|c| match &*c.borrow() {
            Some(fcx) => {
                fcx.fill_random(buf);
                Ok(())
            }
            None => Err(GetRandomFailed),
        })
    }
}

/// Builds the run-aware TLS crypto provider.
///
/// Cipher suites, verification algorithms and their preference order are
/// ring's. Key exchange and signing use the run's entropy through
/// [`with_context`]; without a context, operations needing entropy fail.
/// X25519, P-256 and P-384 secrets are zeroized when dropped. The provider
/// does not install a stateless ticketer; rustls's stateful cache remains
/// available. Custom resolvers and signers must honor the same contract.
///
/// The provider supplies cryptography, not the certificate clock. For a
/// client config, use `rustls::ClientConfig::builder_with_details` with a
/// `TimeProvider` derived from [`Cx::now`] and the world's date.
pub fn crypto_provider() -> CryptoProvider {
    CryptoProvider {
        secure_random: &CxRandom,
        kx_groups: vec![
            &CxGroup(rustls::NamedGroup::X25519),
            &CxGroup(rustls::NamedGroup::secp256r1),
            &CxGroup(rustls::NamedGroup::secp384r1),
        ],
        key_provider: &CxKeyProvider,
        ..rustls::crypto::ring::default_provider()
    }
}

#[derive(Debug)]
struct CxGroup(NamedGroup);

impl SupportedKxGroup for CxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = match self.0 {
            NamedGroup::X25519 => {
                let mut bytes = Zeroizing::new([0; 32]);
                CxRandom.fill(bytes.as_mut())?;
                ExchangeSecret::X25519(x25519_dalek::StaticSecret::from(*bytes))
            }
            NamedGroup::secp256r1 => loop {
                let mut bytes = Zeroizing::new([0; 32]);
                CxRandom.fill(bytes.as_mut())?;
                if let Ok(secret) = p256::SecretKey::from_slice(bytes.as_ref()) {
                    break ExchangeSecret::P256(secret);
                }
            },
            NamedGroup::secp384r1 => loop {
                let mut bytes = Zeroizing::new([0; 48]);
                CxRandom.fill(bytes.as_mut())?;
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
struct CxKeyProvider;

// Debug deliberately excludes private key material.
enum KeyMaterial {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Rsa(Box<rsa::RsaPrivateKey>),
}

struct RunSigningKey {
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

// Own the capability for the duration of the primitive's synchronous call.
// rand_core's infallible methods cannot report missing context, so construction
// checks it before passing this adapter to RSA.
struct CxRng(Cx);
impl CxRng {
    fn current() -> Result<Self, rustls::Error> {
        CURRENT
            .with(|c| c.borrow().clone())
            .map(Self)
            .ok_or_else(|| GetRandomFailed.into())
    }
}
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
                let mut rng = CxRng::current()?;
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
    fn randomness_requires_context_and_preserves_partial_fills() {
        use fictionet::{Entropy, SeededEntropy};
        use rustls::crypto::SecureRandom;
        let mut byte = [0; 1];
        assert!(super::CxRandom.fill(&mut byte).is_err());
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(42),
            |fcx| async move {
                let oracle = SeededEntropy::new(fictionet::Seed::from_u64(42));
                let mut expected = [0; 1];
                oracle.fill_random(&mut expected);
                super::with_context(&fcx, || super::CxRandom.fill(&mut byte)).unwrap();
                assert_eq!(byte, expected);
                assert_eq!(fcx.random_u64(), oracle.random_u64());
                Ok(())
            },
        ))
        .unwrap();
        assert!(super::CxRandom.fill(&mut byte).is_err());
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
                *output.lock().unwrap() =
                    super::with_context(&cx, || draw(super::crypto_provider()));
                Ok(())
            }))
            .unwrap();
            Arc::try_unwrap(result).unwrap().into_inner().unwrap()
        };
        assert_eq!(exercise(91), exercise(91));
        assert_ne!(exercise(91), exercise(92));
    }
}
