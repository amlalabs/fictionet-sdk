//! TLS: the server side of a TLS connection, played by the world.
//!
//! Use this module when a machine in the world serves HTTPS, or any other
//! protocol over TLS, by hand. If the world is a set of websites,
//! [`web::Sites`](https://docs.rs/fictionet/latest/fictionet/stdlib/web/struct.Sites.html) does TLS for you.
//!
//! TLS here is middleware. It takes a [`Connection`], usually a
//! [`TcpConnection`](fictionet::stdlib::tcp::TcpConnection), and gives back a
//! `Connection` that carries the decrypted bytes.
//!
//! The world supplies a rustls [`ServerConfig`], using certificate files
//! or certificates issued by [`ca`](fictionet::stdlib::ca). This module
//! handles the TLS connection.
//!
//! The handshake has two steps, so the world can decide how to answer after
//! it sees what the client asked for. [`server`] reads the client's hello,
//! and [`ClientHello::finish`] completes the handshake with the config the
//! world picks. In this example, the world serves a fake certificate on
//! one connection in ten:
//!
//! ```
//! # use std::sync::Arc;
//! # use fictionet::Cx;
//! # use fictionet::stdlib::{tcp, tls, Connection};
//! # use rustls::ServerConfig;
//! # async fn serve_stripe(_fcx: &Cx, _conn: impl Connection) {}
//! # async fn accept(fcx: Cx, mut listener: tcp::Listener, real: Arc<ServerConfig>, fake: Arc<ServerConfig>) {
//! while let Ok(tcp) = listener.accept(&fcx).await {
//!     let (real, fake) = (real.clone(), fake.clone()); // Arc<ServerConfig>s
//!     fcx.spawn(move |fcx| async move {
//!         // Reads the client's hello. Nothing is sent to the client yet.
//!         // One bad connection is not a failure of the world, so errors end
//!         // this task with Ok(()).
//!         let Ok(hello) = tls::server(&fcx, tcp).await else { return Ok(()) };
//!
//!         // A fake certificate 10% of the time.
//!         let config = if fcx.random_f64() < 0.1 { fake } else { real };
//!
//!         let Ok(conn) = hello.finish(&fcx, config).await else { return Ok(()) };
//!         serve_stripe(&fcx, conn).await;
//!         Ok(())
//!     });
//! }
//! # }
//! ```
//!
//! A world that always uses one config writes the same two steps and never
//! looks at the hello.
//!
//! This module is the simplest way to serve TLS, not the only one. A world
//! can run rustls, OpenSSL, or anything else over a connection itself,
//! since [`Connection`] is an open trait.

use std::cell::RefCell;
use std::future::poll_fn;
use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

pub use rustls::ServerConfig;

use p256::elliptic_curve::{sec1::ToEncodedPoint, zeroize::Zeroizing};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::{Acceptor, ServerConnection};
use rustls::sign::{Signer, SigningKey};
use rustls::time_provider::TimeProvider;
use rustls::{ConfigBuilder, NamedGroup, SignatureAlgorithm, SignatureScheme, WantsVersions};

use fictionet::Cx;
use fictionet::stdlib::{ConnError, Connection};

/// The name of a TLS alert, or "unknown" for an unrecognized code.
pub fn alert_name(code: u8) -> &'static str {
    match code {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        21 => "decryption_failed",
        22 => "record_overflow",
        30 => "decompression_failure",
        40 => "handshake_failure",
        41 => "no_certificate",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        49 => "access_denied",
        50 => "decode_error",
        51 => "decrypt_error",
        60 => "export_restriction",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        100 => "no_renegotiation",
        109 => "missing_extension",
        110 => "unsupported_extension",
        111 => "certificate_unobtainable",
        112 => "unrecognized_name",
        113 => "bad_certificate_status_response",
        114 => "bad_certificate_hash_value",
        115 => "unknown_psk_identity",
        116 => "certificate_required",
        117 => "general_error",
        120 => "no_application_protocol",
        121 => "ech_required",
        _ => "unknown",
    }
}

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
/// Random values are drawn while [`server`], [`ClientHello::finish`] or a
/// [`TlsConnection`] is working, and come from the `Cx` passed to that call.
/// Code driving rustls directly must bind a `Cx` with [`with_context`];
/// otherwise random draws fail.
///
/// Continue as with `ServerConfig::builder()`. Key loading does not draw
/// randomness. Keep configs within their run because the clock holds `fcx`:
///
/// ```
/// # use fictionet::{Cx, Result, stdlib::tls};
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
            ExchangeSecret::P256(s) => s.public_key().to_encoded_point(false).as_bytes().to_vec(),
            ExchangeSecret::P384(s) => s.public_key().to_encoded_point(false).as_bytes().to_vec(),
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
        use rsa::signature::hazmat::PrehashSigner;
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

/// How much to read from the connection underneath in one read.
const READ_CHUNK: usize = 16 * 1024;
/// The most plaintext one `poll_write` encrypts.
const WRITE_CHUNK: usize = 64 * 1024;

/// The byte plumbing between rustls and the connection underneath.
struct Io<C> {
    conn: C,
    /// Bytes read from `conn` that rustls has not taken yet.
    inbuf: Vec<u8>,
    /// Encrypted bytes for `conn` that it has not taken yet, from `out_pos`.
    out: Vec<u8>,
    out_pos: usize,
    /// `conn` said it will send nothing more.
    eof: bool,
}

impl<C: Connection> Io<C> {
    fn new(conn: C) -> Self {
        Io {
            conn,
            inbuf: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            eof: false,
        }
    }

    /// Hands all of `out` to `conn`.
    fn poll_flush(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        while self.out_pos < self.out.len() {
            match self.conn.poll_write(fcx, cx, &self.out[self.out_pos..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(ConnError::Closed)),
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Reads more bytes from `conn` into `inbuf`, or sets `eof`.
    fn poll_fill(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        let old = self.inbuf.len();
        self.inbuf.resize(old + READ_CHUNK, 0);
        let result = self.conn.poll_read(fcx, cx, &mut self.inbuf[old..]);
        let n = match &result {
            Poll::Ready(Ok(n)) => *n,
            _ => 0,
        };
        self.inbuf.truncate(old + n);
        match result {
            Poll::Ready(Ok(0)) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Moves what rustls wants to send into `out`.
    fn take_output(&mut self, tls: &mut ServerConnection) {
        while tls.wants_write() {
            if tls.write_tls(&mut self.out).is_err() {
                break;
            }
        }
    }

    /// Feeds `inbuf` (or the end of input) to rustls and processes it. On a
    /// TLS error, queues the alert rustls made and fails with what went
    /// wrong.
    fn feed(&mut self, fcx: &Cx, tls: &mut ServerConnection) -> Result<(), HandshakeError> {
        if self.inbuf.is_empty() {
            if self.eof {
                // Tells rustls the input ended.
                let _ = tls.read_tls(&mut &[][..]);
            }
        } else {
            let n = tls
                .read_tls(&mut &self.inbuf[..])
                .map_err(|e| HandshakeError::Failed(e.to_string()))?;
            if n == 0 {
                return Err(HandshakeError::Failed("rustls took no bytes".into()));
            }
            self.inbuf.drain(..n);
        }
        let result = with_context(fcx, || tls.process_new_packets().map(|_| ()));
        if let Err(e) = result {
            self.take_output(tls);
            return Err(match e {
                rustls::Error::AlertReceived(alert) => HandshakeError::Alert(u8::from(alert)),
                e => HandshakeError::Failed(e.to_string()),
            });
        }
        Ok(())
    }
}

/// How a handshake failed, in more detail than [`ConnError`]: what
/// [`server_detailed`], [`ClientHello::finish_detailed`] and
/// [`serve::accept_tls`](fictionet::stdlib::serve::accept_tls) return, for a
/// world that logs how each handshake ended.
#[derive(Debug)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The client closed the connection before the handshake finished.
    Closed,
    /// The client sent this fatal alert.
    Alert(u8),
    /// The bytes were not TLS, or broke the protocol.
    Failed(String),
    /// There was no config for the name the client asked for, and the
    /// handshake was refused with `unrecognized_name`. Only from
    /// `accept_tls`.
    Rejected,
    /// The handshake did not finish by its deadline. Only from
    /// `accept_tls`.
    TimedOut,
    /// The connection underneath failed. Never [`ConnError::Cancelled`]:
    /// a cancel is [`HandshakeError::Cancelled`].
    Conn(ConnError),
    /// The [region](fictionet::Cx#regions) of the `Cx` passed to the call was
    /// cancelled while it waited.
    Cancelled,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Closed => {
                f.write_str("the client closed the connection before the handshake finished")
            }
            HandshakeError::Alert(a) => write!(f, "the client sent alert {a}"),
            HandshakeError::Failed(why) => f.write_str(why),
            HandshakeError::Rejected => {
                f.write_str("there is no TLS config for the name the client asked for")
            }
            HandshakeError::TimedOut => f.write_str("the handshake did not finish in time"),
            HandshakeError::Conn(_) => f.write_str("the connection failed during the handshake"),
            HandshakeError::Cancelled => f.write_str("the handshake stopped"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HandshakeError::Conn(e) => Some(e),
            HandshakeError::Cancelled => Some(&fictionet::Cancelled),
            _ => None,
        }
    }
}

impl From<ConnError> for HandshakeError {
    /// A connection's error, with a cancel as [`HandshakeError::Cancelled`].
    fn from(e: ConnError) -> Self {
        match e {
            ConnError::Cancelled => HandshakeError::Cancelled,
            e => HandshakeError::Conn(e),
        }
    }
}

impl From<fictionet::Cancelled> for HandshakeError {
    fn from(_: fictionet::Cancelled) -> Self {
        HandshakeError::Cancelled
    }
}

impl HandshakeError {
    fn into_conn(self) -> ConnError {
        match self {
            HandshakeError::Conn(e) => e,
            HandshakeError::Cancelled => ConnError::Cancelled,
            HandshakeError::TimedOut => ConnError::TimedOut,
            _ => ConnError::Broken,
        }
    }
}

/// Starts the server side of a TLS handshake on `conn`.
///
/// Waits for the client's first message, its hello, reads it, and returns.
/// Nothing has been sent to the client yet. Finish the handshake with
/// [`ClientHello::finish`], or drop the hello to close the connection.
///
/// Fails with [`ConnError::Broken`] if the client's first message is not a
/// TLS hello, or if the client closes the connection before it sent a whole
/// hello. An error of the connection underneath, such as
/// [`ConnError::Cancelled`] when `fcx`'s [region](fictionet::Cx#regions) is
/// cancelled, comes out as it is.
pub async fn server<C: Connection>(fcx: &Cx, conn: C) -> Result<ClientHello<C>, ConnError> {
    server_detailed(fcx, conn)
        .await
        .map_err(HandshakeError::into_conn)
}

/// [`server`], failing with how the hello went wrong.
pub async fn server_detailed<C: Connection>(
    fcx: &Cx,
    conn: C,
) -> Result<ClientHello<C>, HandshakeError> {
    let mut io = Io::new(conn);
    let mut acceptor = Acceptor::default();
    let accepted = poll_fn(|cx| {
        loop {
            if !io.inbuf.is_empty() {
                let n = acceptor
                    .read_tls(&mut &io.inbuf[..])
                    .map_err(|e| HandshakeError::Failed(e.to_string()))?;
                io.inbuf.drain(..n);
                match acceptor.accept() {
                    Ok(Some(accepted)) => return Poll::Ready(Ok(accepted)),
                    Ok(None) if n == 0 => {
                        return Poll::Ready(Err(HandshakeError::Failed(
                            "the hello is too large".into(),
                        )));
                    }
                    Ok(None) => continue,
                    // Not a TLS hello. Nothing is sent: the connection closes.
                    Err((e, _)) => return Poll::Ready(Err(HandshakeError::Failed(e.to_string()))),
                }
            }
            if io.eof {
                return Poll::Ready(Err(HandshakeError::Closed));
            }
            match io.poll_fill(fcx, cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await?;
    let hello = accepted.client_hello();
    let server_name = hello.server_name().map(str::to_owned);
    let alpn = hello
        .alpn()
        .map(|protocols| protocols.map(<[u8]>::to_vec).collect())
        .unwrap_or_default();
    Ok(ClientHello {
        conn: io.conn,
        inbuf: io.inbuf,
        accepted,
        server_name,
        alpn,
    })
}

/// What the client asked for, before the server has answered.
pub struct ClientHello<C> {
    conn: C,
    /// Bytes the client sent after its hello, not yet read by rustls.
    inbuf: Vec<u8>,
    accepted: rustls::server::Accepted,
    server_name: Option<String>,
    alpn: Vec<Vec<u8>>,
}

/// The `unrecognized_name` alert (112) as a fatal alert record, unencrypted,
/// as it is sent before the server's hello.
const UNRECOGNIZED_NAME: [u8; 7] = [21, 3, 3, 0, 2, 2, 112];

impl<C: Connection> ClientHello<C> {
    /// The name the client asked for (SNI), such as `api.stripe.com`. `None`
    /// if the client sent no name, for example when it connected to a bare
    /// IP address.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// The application protocols the client offers (ALPN), such as `h2` and
    /// `http/1.1`, in the client's order of preference.
    pub fn alpn(&self) -> Vec<&[u8]> {
        self.alpn.iter().map(Vec::as_slice).collect()
    }

    /// The connection underneath, for example to see who connected.
    pub fn inner(&self) -> &C {
        &self.conn
    }

    /// Refuses the name the client asked for: sends the `unrecognized_name`
    /// alert and closes the connection. Dropping the hello instead closes the
    /// connection with no alert.
    pub async fn reject(self, fcx: &Cx) -> Result<(), ConnError> {
        use fictionet::stdlib::ConnectionExt;
        let mut conn = self.conn;
        conn.write_all(fcx, &UNRECOGNIZED_NAME).await?;
        conn.shutdown(fcx).await
    }

    /// Finishes the handshake with `config`.
    ///
    /// Fails with [`ConnError::Broken`] if the handshake fails, for example
    /// because the client rejected the certificate. An error of the
    /// connection underneath comes out as it is.
    pub async fn finish(
        self,
        fcx: &Cx,
        config: Arc<ServerConfig>,
    ) -> Result<TlsConnection<C>, ConnError> {
        self.finish_detailed(fcx, config)
            .await
            .map_err(HandshakeError::into_conn)
    }

    /// [`finish`](ClientHello::finish), failing with how the handshake went
    /// wrong.
    pub async fn finish_detailed(
        self,
        fcx: &Cx,
        config: Arc<ServerConfig>,
    ) -> Result<TlsConnection<C>, HandshakeError> {
        let mut io = Io {
            conn: self.conn,
            inbuf: self.inbuf,
            out: Vec::new(),
            out_pos: 0,
            eof: false,
        };
        let config = fictionet::observe::observed_config(fcx, config);
        let mut tls = match with_context(fcx, || self.accepted.into_connection(config)) {
            Ok(tls) => tls,
            Err((e, mut alert)) => {
                // Best effort: tell the client why, then close.
                let _ = alert.write_all(&mut io.out);
                let _ = poll_fn(|cx| io.poll_flush(fcx, cx)).await;
                return Err(HandshakeError::Failed(e.to_string()));
            }
        };
        let result = poll_fn(|cx| {
            loop {
                io.take_output(&mut tls);
                match io.poll_flush(fcx, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => return Poll::Pending,
                }
                if !tls.is_handshaking() {
                    return Poll::Ready(Ok(()));
                }
                if !io.inbuf.is_empty() {
                    io.feed(fcx, &mut tls)?;
                    continue;
                }
                if io.eof {
                    return Poll::Ready(Err(HandshakeError::Closed));
                }
                match io.poll_fill(fcx, cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
        match result {
            Ok(()) => Ok(TlsConnection {
                io,
                tls,
                taken: None,
                closing: false,
            }),
            Err(e) => {
                // Send the alert rustls made, if there is one.
                if !io.out.is_empty() {
                    let _ = poll_fn(|cx| io.poll_flush(fcx, cx)).await;
                }
                Err(e)
            }
        }
    }
}

/// A finished TLS connection. Reads and writes carry the decrypted bytes.
pub struct TlsConnection<C> {
    io: Io<C>,
    tls: ServerConnection,
    /// Plaintext rustls has encrypted for an earlier `poll_write` whose
    /// output `conn` has not taken yet. Reported as taken once it has.
    taken: Option<Vec<u8>>,
    /// `close_notify` is queued.
    closing: bool,
}

impl<C: Connection> TlsConnection<C> {
    /// The connection underneath.
    pub fn inner(&self) -> &C {
        &self.io.conn
    }

    /// The application protocol both sides agreed on (ALPN), if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn_protocol()
    }
}

impl<C: Connection> Connection for TlsConnection<C> {
    fn poll_read(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ConnError>> {
        // A cancel comes first, before plaintext already decrypted.
        if fcx.is_cancelled() {
            return Poll::Ready(Err(ConnError::Cancelled));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match self.tls.reader().read(buf) {
                // Ok(0) is the client's close_notify.
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                // The client closed the connection without close_notify.
                // A server reads that as the end of input, like most do.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Poll::Ready(Ok(0)),
                Err(_) => return Poll::Ready(Err(ConnError::Broken)),
            }
            if !self.io.inbuf.is_empty() || self.io.eof {
                let eof_seen = self.io.inbuf.is_empty();
                let fed = self.io.feed(fcx, &mut self.tls);
                // rustls may have something to send: a key update, a ticket
                // or an alert. Hand it on if `conn` has room now; otherwise
                // the next write or read sends it.
                self.io.take_output(&mut self.tls);
                let _ = self.io.poll_flush(fcx, cx);
                if fed.is_err() {
                    return Poll::Ready(Err(ConnError::Broken));
                }
                if eof_seen {
                    // The end of input was fed; the reader now says how it
                    // ended. Never loop on it twice.
                    return match self.tls.reader().read(buf) {
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(e)
                            if e.kind() == ErrorKind::WouldBlock
                                || e.kind() == ErrorKind::UnexpectedEof =>
                        {
                            Poll::Ready(Ok(0))
                        }
                        Err(_) => Poll::Ready(Err(ConnError::Broken)),
                    };
                }
                continue;
            }
            match self.io.poll_fill(fcx, cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    // Output queued by an earlier read still goes out.
                    let _ = self.io.poll_flush(fcx, cx);
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_write(
        &mut self,
        fcx: &Cx,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, ConnError>> {
        if let Some(previous) = self.taken.as_ref() {
            let same = data.starts_with(previous);
            let n = previous.len();
            // Credit an earlier write only when these are its bytes.
            match self.io.poll_flush(fcx, cx) {
                Poll::Ready(Ok(())) => {
                    self.taken = None;
                    if same {
                        return Poll::Ready(Ok(n));
                    }
                }
                other => return other.map(|r| r.map(|()| 0)),
            }
        }
        if self.closing {
            return Poll::Ready(Err(ConnError::Closed));
        }
        match self.io.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => {}
            other => return other.map(|r| r.map(|()| 0)),
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &data[..data.len().min(WRITE_CHUNK)];
        let n = match with_context(fcx, || self.tls.writer().write(chunk)) {
            Ok(0) | Err(_) => return Poll::Ready(Err(ConnError::Closed)),
            Ok(n) => n,
        };
        self.io.take_output(&mut self.tls);
        match self.io.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                self.taken = Some(chunk[..n].to_vec());
                Poll::Pending
            }
        }
    }

    /// Sends `close_notify`, then shuts down the connection underneath.
    fn poll_shutdown(&mut self, fcx: &Cx, cx: &mut Context<'_>) -> Poll<Result<(), ConnError>> {
        if !self.closing {
            self.closing = true;
            with_context(fcx, || self.tls.send_close_notify());
            self.io.take_output(&mut self.tls);
        }
        match self.io.poll_flush(fcx, cx) {
            Poll::Ready(Ok(())) => self.io.conn.poll_shutdown(fcx, cx),
            other => other,
        }
    }

    fn poll_gone(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.io.conn.poll_gone(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::alert_name;

    #[test]
    fn randomness_requires_context_and_preserves_partial_fills() {
        use fictionet::{Entropy, Seed, SeededEntropy};
        use rustls::crypto::SecureRandom;
        let mut byte = [0; 1];
        assert!(super::CxRandom.fill(&mut byte).is_err());
        fictionet::block_on(fictionet::lab(Seed::from_u64(42), |fcx| async move {
            let oracle = SeededEntropy::new(Seed::from_u64(42));
            let mut expected = [0; 1];
            oracle.fill_random(&mut expected);
            super::with_context(&fcx, || super::CxRandom.fill(&mut byte)).unwrap();
            assert_eq!(byte, expected);
            assert_eq!(fcx.random_u64(), oracle.random_u64());
            Ok(())
        }))
        .unwrap();
        assert!(super::CxRandom.fill(&mut byte).is_err());
    }

    #[test]
    fn tls_alert_names() {
        let known = [
            (0, "close_notify"),
            (10, "unexpected_message"),
            (20, "bad_record_mac"),
            (21, "decryption_failed"),
            (22, "record_overflow"),
            (30, "decompression_failure"),
            (40, "handshake_failure"),
            (41, "no_certificate"),
            (42, "bad_certificate"),
            (43, "unsupported_certificate"),
            (44, "certificate_revoked"),
            (45, "certificate_expired"),
            (46, "certificate_unknown"),
            (47, "illegal_parameter"),
            (48, "unknown_ca"),
            (49, "access_denied"),
            (50, "decode_error"),
            (51, "decrypt_error"),
            (60, "export_restriction"),
            (70, "protocol_version"),
            (71, "insufficient_security"),
            (80, "internal_error"),
            (86, "inappropriate_fallback"),
            (90, "user_canceled"),
            (100, "no_renegotiation"),
            (109, "missing_extension"),
            (110, "unsupported_extension"),
            (111, "certificate_unobtainable"),
            (112, "unrecognized_name"),
            (113, "bad_certificate_status_response"),
            (114, "bad_certificate_hash_value"),
            (115, "unknown_psk_identity"),
            (116, "certificate_required"),
            (117, "general_error"),
            (120, "no_application_protocol"),
            (121, "ech_required"),
        ];
        for code in 0..=u8::MAX {
            let expected = known
                .iter()
                .find(|(c, _)| *c == code)
                .map_or("unknown", |(_, name)| *name);
            assert_eq!(alert_name(code), expected, "alert {code}");
        }
    }
}
