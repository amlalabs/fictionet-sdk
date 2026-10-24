//! Certificate authorities for simulated TLS sites.
//!
//! Keys and serial numbers come from the run's seeded randomness. A root
//! made by [`Ca::new`] is valid from 2000 through 2100. Leaf validity is
//! chosen by the world, independently of the host's clock.

use std::sync::Arc;
use std::time::SystemTime;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::asn1::{BitString, Oid, StringKind, Writer};
use fictionet::stdlib::{protocols::x509, services::tls};
use fictionet::{Cx, Error};
use p256::ecdsa::signature::Signer;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs8::DecodePrivateKey as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use x509::{ExtensionValue, oid};

/// The DER NULL element used for RSA algorithm parameters.
const NULL_PARAMETERS: &[u8] = &[0x05, 0x00];

/// The key type and signature algorithm used by a CA.
#[derive(Clone, Copy, Debug)]
pub enum KeyKind {
    /// P-256 keys with ECDSA-SHA256 signatures.
    P256,
    /// P-384 keys with ECDSA-SHA384 signatures.
    P384,
    /// RSA 2048-bit keys with RSASSA-PKCS1-v1_5 SHA-256 signatures.
    Rsa2048,
}

/// A certificate authority and its signing key.
pub struct Ca {
    certificate: x509::Certificate,
    key: Key,
}

/// A server certificate chain, key, and validity interval.
pub struct Leaf {
    /// The leaf followed by its issuing CAs.
    pub chain: Vec<CertificateDer<'static>>,
    /// The leaf's private key.
    pub key: PrivateKeyDer<'static>,
    /// The dates supplied when the leaf was issued.
    pub validity: x509::Validity,
}

fn id(bytes: &[u8]) -> Oid {
    Oid::from_contents(bytes).expect("a certificate algorithm identifier")
}

enum Key {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Rsa(Box<rsa::RsaPrivateKey>),
}

/// A deterministic random source for RSA key generation, so a seeded run
/// makes the same key every time, as the EC paths do with `fill_random`.
struct SeededRng<'a>(&'a Cx);

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

impl Key {
    fn new(fcx: &Cx, kind: KeyKind) -> Self {
        match kind {
            KeyKind::P256 => loop {
                let mut bytes = [0; 32];
                fcx.fill_random(&mut bytes);
                if let Ok(key) = p256::ecdsa::SigningKey::from_bytes((&bytes).into()) {
                    break Self::P256(key);
                }
            },
            KeyKind::P384 => loop {
                let mut bytes = [0; 48];
                fcx.fill_random(&mut bytes);
                if let Ok(key) = p384::ecdsa::SigningKey::from_bytes((&bytes).into()) {
                    break Self::P384(key);
                }
            },
            KeyKind::Rsa2048 => Self::Rsa(Box::new(
                rsa::RsaPrivateKey::new(&mut SeededRng(fcx), 2048)
                    .expect("RSA 2048 key generation"),
            )),
        }
    }

    fn algorithm(&self) -> x509::AlgorithmIdentifier {
        match self {
            Self::P256(_) => x509::AlgorithmIdentifier {
                oid: id(oid::ECDSA_WITH_SHA256),
                parameters: None,
            },
            Self::P384(_) => x509::AlgorithmIdentifier {
                oid: id(oid::ECDSA_WITH_SHA384),
                parameters: None,
            },
            // RFC 4055 section 5: RSA signature parameters are NULL.
            Self::Rsa(_) => x509::AlgorithmIdentifier {
                oid: id(oid::SHA256_WITH_RSA),
                parameters: Some(NULL_PARAMETERS.to_vec()),
            },
        }
    }

    /// The subject public key info: the algorithm with its parameters, and
    /// the key in that algorithm's own encoding.
    fn public_key_info(&self) -> x509::PublicKeyInfo {
        let (algorithm, key) = match self {
            Self::P256(k) => (
                x509::AlgorithmIdentifier {
                    oid: id(oid::EC_PUBLIC_KEY),
                    parameters: Some(curve_parameters(oid::PRIME256V1)),
                },
                k.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
            ),
            Self::P384(k) => (
                x509::AlgorithmIdentifier {
                    oid: id(oid::EC_PUBLIC_KEY),
                    parameters: Some(curve_parameters(oid::SECP384R1)),
                },
                k.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
            ),
            // RFC 4055 section 1.2: the algorithm is rsaEncryption with NULL
            // parameters, and the key is the DER of RSAPublicKey.
            Self::Rsa(k) => (
                x509::AlgorithmIdentifier {
                    oid: id(oid::RSA_ENCRYPTION),
                    parameters: Some(NULL_PARAMETERS.to_vec()),
                },
                k.to_public_key()
                    .to_pkcs1_der()
                    .expect("an RSA public key encodes")
                    .as_bytes()
                    .to_vec(),
            ),
        };
        x509::PublicKeyInfo {
            algorithm,
            key: BitString::new(key, 0).expect("a public key is whole bytes"),
        }
    }

    fn der(&self) -> Result<p256::pkcs8::SecretDocument, Error> {
        Ok(match self {
            Self::P256(key) => key.to_pkcs8_der()?,
            Self::P384(key) => key.to_pkcs8_der()?,
            Self::Rsa(key) => p256::pkcs8::SecretDocument::try_from(
                rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(key.as_ref())?.as_bytes(),
            )?,
        })
    }
}

/// The DER of a named-curve parameter: the curve's object identifier.
fn curve_parameters(curve: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.oid(&id(curve));
    writer.finish().expect("a certificate curve identifier")
}

fn subject(cn: &str) -> x509::Name {
    let mut name = x509::Name::default();
    name.push(
        id(oid::COMMON_NAME),
        x509::Value::Text {
            kind: StringKind::Utf8,
            text: cn.chars().take(64).collect(),
        },
    );
    name
}

fn tbs(fcx: &Cx, key: &Key, name: x509::Name, validity: x509::Validity) -> x509::TbsCertificate {
    let mut serial = vec![0; 16];
    fcx.fill_random(&mut serial);
    serial[0] = (serial[0] & 0x7f) | 1;
    x509::TbsCertificate {
        version: x509::Version::V3,
        serial,
        signature: key.algorithm(),
        issuer: name.clone(),
        validity,
        subject: name,
        public_key: key.public_key_info(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Vec::new(),
    }
}

fn sign(key: &Key, tbs: x509::TbsCertificate) -> Result<x509::Certificate, Error> {
    let bytes = tbs.to_bytes()?;
    let signature = match key {
        Key::P256(key) => {
            let signature: p256::ecdsa::Signature = key.sign(&bytes);
            signature.to_der().as_bytes().to_vec()
        }
        Key::P384(key) => {
            let signature: p384::ecdsa::Signature = key.sign(&bytes);
            signature.to_der().as_bytes().to_vec()
        }
        Key::Rsa(key) => {
            // RSASSA-PKCS1-v1_5 over the SHA-256 of the signed bytes.
            let hash = ring::digest::digest(&ring::digest::SHA256, &bytes);
            key.sign(rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(), hash.as_ref())?
        }
    };
    Ok(x509::Certificate::assemble(
        &bytes,
        key.algorithm(),
        BitString::new(signature, 0)?,
    )?)
}

/// A key that signs certificates, the primitive under [`Ca`]. A world
/// reaches for it only when it must build a certificate chain field by
/// field, such as a look-alike enterprise CA whose exact subject names,
/// extensions and criticality a sandboxed client should recognize. For an
/// ordinary simulated site, [`Ca`] is simpler.
///
/// Keys and signatures are deterministic in `fcx`'s seed, so a seeded run
/// makes the same chain every time.
pub struct SigningKey(Key);

impl SigningKey {
    /// Generates a key of `kind` from `fcx`'s randomness.
    pub fn generate(fcx: &Cx, kind: KeyKind) -> SigningKey {
        SigningKey(Key::new(fcx, kind))
    }

    /// The signature algorithm this key signs with, for a certificate's
    /// `signature` field (which must match, or signing fails).
    pub fn algorithm(&self) -> x509::AlgorithmIdentifier {
        self.0.algorithm()
    }

    /// The subject public key info to put in a certificate this key is for.
    pub fn public_key_info(&self) -> x509::PublicKeyInfo {
        self.0.public_key_info()
    }

    /// The subject (and, from the issuer's key, authority) key identifier:
    /// the SHA-1 of the subject public key, as issuers compute it.
    pub fn key_identifier(&self) -> Vec<u8> {
        ring::digest::digest(
            &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            self.public_key_info().key.bytes(),
        )
        .as_ref()
        .to_vec()
    }

    /// Signs `tbs` with this key and assembles the certificate. The caller
    /// sets every field, including `tbs.signature`, which must be
    /// [`algorithm`](Self::algorithm). No extension is added or changed.
    pub fn sign(&self, tbs: x509::TbsCertificate) -> Result<x509::Certificate, Error> {
        sign(&self.0, tbs)
    }

    /// The private key as PKCS#8 DER, for a server configuration.
    pub fn private_key_der(&self) -> Result<PrivatePkcs8KeyDer<'static>, Error> {
        Ok(PrivatePkcs8KeyDer::from(self.0.der()?.as_bytes().to_vec()))
    }
}

impl Ca {
    /// Makes a self-signed root with a key from `fcx`.
    pub fn new(fcx: &Cx, common_name: &str) -> Result<Self, Error> {
        Self::self_signed(
            fcx,
            subject(common_name),
            x509::Validity {
                not_before: x509::Time::from_unix(946684800)?,
                not_after: x509::Time::from_unix(4102444800)?,
            },
            None,
            KeyKind::P256,
        )
    }

    /// Makes a self-signed CA with the given subject, validity, path length, and key type.
    pub fn self_signed(
        fcx: &Cx,
        subject: x509::Name,
        validity: x509::Validity,
        path_len: Option<u64>,
        kind: KeyKind,
    ) -> Result<Self, Error> {
        let key = Key::new(fcx, kind);
        let mut tbs = tbs(fcx, &key, subject, validity);
        let mut identifier = vec![0; 20];
        fcx.fill_random(&mut identifier);
        tbs.extensions = vec![
            x509::SubjectKeyIdentifier(identifier).to_extension(false)?,
            x509::BasicConstraints { ca: true, path_len }.to_extension(true)?,
            x509::KeyUsage(x509::KeyUsage::KEY_CERT_SIGN | x509::KeyUsage::CRL_SIGN)
                .to_extension(true)?,
        ];
        let certificate = sign(&key, tbs)?;
        Ok(Self { certificate, key })
    }

    /// Reads a CA certificate and its PKCS#8 P-256, P-384, or RSA key from PEM text.
    /// Fails if the certificate is not a CA or its public key differs.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Error> {
        let certificate = x509::Certificate::from_pem(cert_pem.as_bytes())?;
        let key = match p256::ecdsa::SigningKey::from_pkcs8_pem(key_pem) {
            Ok(key) => Key::P256(key),
            Err(_) => match p384::ecdsa::SigningKey::from_pkcs8_pem(key_pem) {
                Ok(key) => Key::P384(key),
                Err(_) => Key::Rsa(Box::new(rsa::RsaPrivateKey::from_pkcs8_pem(key_pem)?)),
            },
        };
        let public_key = key.public_key_info();
        if !certificate
            .tbs
            .get::<x509::BasicConstraints>()?
            .is_some_and(|c| c.ca)
            || certificate.tbs.public_key != public_key
        {
            return Err(Error::msg("CA certificate and key do not match"));
        }
        Ok(Self { certificate, key })
    }

    /// The CA certificate as PEM text.
    pub fn cert_pem(&self) -> String {
        String::from_utf8(
            x509::PemBlock::new("CERTIFICATE", &self.certificate)
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap()
    }

    /// The private signing key as PKCS#8 PEM text, for worlds that persist a CA.
    pub fn key_pem(&self) -> String {
        self.key
            .der()
            .unwrap()
            .to_pem("PRIVATE KEY", p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    /// The CA certificate as DER bytes.
    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.certificate.to_bytes().unwrap().into()
    }

    /// Issues a server leaf for DNS names and textual IP addresses.
    pub fn issue(&self, fcx: &Cx, names: &[&str], validity: x509::Validity) -> Result<Leaf, Error> {
        let cn = names
            .first()
            .ok_or_else(|| Error::msg("a leaf needs at least one name"))?;
        let key = Key::new(fcx, KeyKind::P256);
        let mut tbs = tbs(fcx, &key, subject(cn), validity.clone());
        let names = x509::SubjectAltName(
            names
                .iter()
                .map(|name| x509::GeneralName::from_host(name))
                .collect(),
        );
        tbs.extensions = vec![
            x509::BasicConstraints {
                ca: false,
                path_len: None,
            }
            .to_extension(true)?,
            names.to_extension(false)?,
            x509::ExtendedKeyUsage(vec![id(oid::SERVER_AUTH)]).to_extension(false)?,
        ];
        let cert = self.sign(tbs)?;
        Ok(Leaf {
            chain: vec![cert.to_bytes()?.into(), self.cert_der()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.der()?.as_bytes().to_vec())),
            validity,
        })
    }

    /// Sets the issuer and signature algorithm, then signs a certificate.
    pub fn sign(&self, mut tbs: x509::TbsCertificate) -> Result<x509::Certificate, Error> {
        if tbs.extension(oid::AUTHORITY_KEY_IDENTIFIER).is_none()
            && let Some(identifier) = self.certificate.tbs.get::<x509::SubjectKeyIdentifier>()?
        {
            tbs.extensions.push(
                x509::AuthorityKeyIdentifier {
                    key_id: Some(identifier.0),
                    issuer: None,
                    serial: None,
                }
                .to_extension(false)?,
            );
        }
        tbs.issuer = self.certificate.tbs.subject.clone();
        tbs.signature = self.key.algorithm();
        sign(&self.key, tbs)
    }
}

impl Leaf {
    /// Builds a TLS server configuration using the run's clock and randomness.
    pub fn server_config(
        self,
        fcx: &Cx,
        start: SystemTime,
    ) -> Result<Arc<tls::ServerConfig>, Error> {
        Ok(Arc::new(
            tls::config_builder(fcx, start)
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(self.chain, self.key)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_ca_pem_round_trip() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(23),
            |fcx| async move {
                let validity = x509::Validity {
                    not_before: x509::Time::from_unix(1_700_000_000)?,
                    not_after: x509::Time::from_unix(2_000_000_000)?,
                };
                let ca = Ca::self_signed(
                    &fcx,
                    subject("RSA CA"),
                    validity.clone(),
                    None,
                    KeyKind::Rsa2048,
                )?;
                let loaded = Ca::from_pem(&ca.cert_pem(), &ca.key_pem())?;
                assert_eq!(loaded.cert_der(), ca.cert_der());
                assert_eq!(loaded.key_pem(), ca.key_pem());
                let other = Ca::new(&fcx, "Other CA")?;
                assert!(Ca::from_pem(&ca.cert_pem(), &other.key_pem()).is_err());
                assert!(Ca::from_pem(&other.cert_pem(), &ca.key_pem()).is_err());
                let leaf = loaded.issue(&fcx, &["example.test"], validity)?;
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca.cert_der())?;
                let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::new(rustls::crypto::ring::default_provider()),
                )
                .build()?;
                use rustls::client::danger::ServerCertVerifier;
                verifier.verify_server_cert(
                    &leaf.chain[0],
                    &[],
                    &"example.test".try_into()?,
                    &[],
                    rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                        1_800_000_000,
                    )),
                )?;
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn p384_ca_signs_a_trusted_p256_leaf() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(19),
            |fcx| async move {
                let validity = x509::Validity {
                    not_before: x509::Time::from_unix(1_700_000_000)?,
                    not_after: x509::Time::from_unix(2_000_000_000)?,
                };
                let name = subject("P-384 CA");
                let ca =
                    Ca::self_signed(&fcx, name.clone(), validity.clone(), Some(0), KeyKind::P384)?;
                let cert = x509::Certificate::parse(&ca.cert_der())?;
                assert_eq!(cert.tbs.subject, name);
                assert_eq!(cert.tbs.issuer, name);
                assert_eq!(cert.tbs.validity, validity);
                assert_eq!(
                    cert.tbs.get::<x509::BasicConstraints>()?.unwrap().path_len,
                    Some(0)
                );
                assert_eq!(cert.tbs.public_key.key.bytes().len(), 97);
                assert_eq!(
                    cert.signature_algorithm.oid.as_bytes(),
                    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3]
                );
                let loaded = Ca::from_pem(&ca.cert_pem(), &ca.key_pem())?;
                let leaf = loaded.issue(&fcx, &["example.test"], validity)?;
                let cert = x509::Certificate::parse(&leaf.chain[0])?;
                assert_eq!(cert.tbs.public_key.key.bytes().len(), 65);
                assert_eq!(cert.signature_algorithm, cert.tbs.signature);
                assert_eq!(
                    cert.signature_algorithm.oid.as_bytes(),
                    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3]
                );
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca.cert_der())?;
                let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::new(rustls::crypto::ring::default_provider()),
                )
                .build()?;
                use rustls::client::danger::ServerCertVerifier;
                verifier.verify_server_cert(
                    &leaf.chain[0],
                    &[],
                    &"example.test".try_into()?,
                    &[],
                    rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                        1_800_000_000,
                    )),
                )?;
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn seeded_issuance_is_repeatable_and_trusted() {
        fn issue() -> Vec<u8> {
            let bytes = Arc::new(fictionet::sync::Mutex::new(Vec::new()));
            let output = bytes.clone();
            fictionet::block_on(fictionet::lab(
                fictionet::Seed::from_u64(17),
                move |fcx| async move {
                    let ca = Ca::new(&fcx, "Test CA")?;
                    let key = ca.key_pem();
                    let loaded = Ca::from_pem(&ca.cert_pem(), &key)?;
                    assert_eq!(loaded.cert_der(), ca.cert_der());
                    let other = Ca::new(&fcx, "Other CA")?;
                    assert!(Ca::from_pem(&other.cert_pem(), &key).is_err());
                    let validity = x509::Validity {
                        not_before: x509::Time::from_unix(1_700_000_000)?,
                        not_after: x509::Time::from_unix(2_000_000_000)?,
                    };
                    let leaf = loaded.issue(&fcx, &["example.test", "203.0.113.10"], validity)?;
                    let mut roots = rustls::RootCertStore::empty();
                    roots.add(ca.cert_der())?;
                    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
                        Arc::new(roots),
                        Arc::new(rustls::crypto::ring::default_provider()),
                    )
                    .build()?;
                    use rustls::client::danger::ServerCertVerifier;
                    let verify = |name: &'static str, time| {
                        verifier.verify_server_cert(
                            &leaf.chain[0],
                            &leaf.chain[1..],
                            &name.try_into().unwrap(),
                            &[],
                            rustls::pki_types::UnixTime::since_unix_epoch(
                                std::time::Duration::from_secs(time),
                            ),
                        )
                    };
                    assert!(verify("example.test", 1_800_000_000).is_ok());
                    assert!(verify("203.0.113.10", 1_800_000_000).is_ok());
                    assert!(verify("other.test", 1_800_000_000).is_err());
                    assert!(verify("example.test", 2_100_000_000).is_err());
                    *output.lock() = leaf.chain[0].to_vec();
                    leaf.server_config(&fcx, SystemTime::UNIX_EPOCH)?;
                    Ok(())
                },
            ))
            .unwrap();
            std::mem::take(Arc::try_unwrap(bytes).unwrap().get_mut())
        }
        assert_eq!(issue(), issue());
    }
}
