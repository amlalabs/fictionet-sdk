//! Certificate authorities for simulated TLS sites.
//!
//! Keys and serial numbers come from the run's seeded randomness. A root
//! made by [`Ca::new`] is valid from 2000 through 2100. Leaf validity is
//! chosen by the world, independently of the host's clock.

use std::sync::Arc;
use std::time::SystemTime;

use fictionet::stdlib::asn1::{BitString, Oid, StringKind, Writer};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::{tls, x509};
use fictionet::{Cx, Error};
use p256::ecdsa::signature::Signer;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use x509::{ExtensionValue, oid};

/// The elliptic curve used for a CA key and its signatures.
#[derive(Clone, Copy, Debug)]
pub enum Curve {
    /// P-256 keys with ECDSA-SHA256 signatures.
    P256,
    /// P-384 keys with ECDSA-SHA384 signatures.
    P384,
}

/// A certificate authority and its signing key.
pub struct Ca {
    certificate: x509::Certificate,
    key: Key,
}

/// A server certificate chain, key, and validity interval.
pub struct Leaf {
    /// The leaf followed by its issuing CA.
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
}

impl Key {
    fn new(fcx: &Cx, curve: Curve) -> Self {
        loop {
            match curve {
                Curve::P256 => {
                    let mut bytes = [0; 32];
                    fcx.fill_random(&mut bytes);
                    if let Ok(key) = p256::ecdsa::SigningKey::from_bytes((&bytes).into()) {
                        return Self::P256(key);
                    }
                }
                Curve::P384 => {
                    let mut bytes = [0; 48];
                    fcx.fill_random(&mut bytes);
                    if let Ok(key) = p384::ecdsa::SigningKey::from_bytes((&bytes).into()) {
                        return Self::P384(key);
                    }
                }
            }
        }
    }

    fn algorithm(&self) -> x509::AlgorithmIdentifier {
        x509::AlgorithmIdentifier {
            oid: id(match self {
                Self::P256(_) => oid::ECDSA_WITH_SHA256,
                Self::P384(_) => oid::ECDSA_WITH_SHA384,
            }),
            parameters: None,
        }
    }

    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::P256(key) => key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            Self::P384(key) => key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        }
    }

    fn parameters(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.oid(&id(match self {
            Self::P256(_) => oid::PRIME256V1,
            Self::P384(_) => oid::SECP384R1,
        }));
        writer.finish().expect("a certificate curve identifier")
    }

    fn der(&self) -> Result<p256::pkcs8::SecretDocument, Error> {
        Ok(match self {
            Self::P256(key) => key.to_pkcs8_der()?,
            Self::P384(key) => key.to_pkcs8_der()?,
        })
    }
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
        public_key: x509::PublicKeyInfo {
            algorithm: x509::AlgorithmIdentifier {
                oid: id(oid::EC_PUBLIC_KEY),
                parameters: Some(key.parameters()),
            },
            key: BitString::new(key.public_key(), 0).unwrap(),
        },
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
    };
    Ok(x509::Certificate::assemble(
        &bytes,
        key.algorithm(),
        BitString::new(signature, 0)?,
    )?)
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
            Curve::P256,
        )
    }

    /// Makes a self-signed CA with the given subject, validity, path length, and curve.
    pub fn self_signed(
        fcx: &Cx,
        subject: x509::Name,
        validity: x509::Validity,
        path_len: Option<u64>,
        curve: Curve,
    ) -> Result<Self, Error> {
        let key = Key::new(fcx, curve);
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

    /// Reads a CA certificate and its PKCS#8 P-256 or P-384 key from PEM text.
    /// Fails if the certificate is not a CA or its public key differs.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Error> {
        let certificate = x509::Certificate::from_pem(cert_pem.as_bytes())?;
        let key = match p256::ecdsa::SigningKey::from_pkcs8_pem(key_pem) {
            Ok(key) => Key::P256(key),
            Err(_) => Key::P384(p384::ecdsa::SigningKey::from_pkcs8_pem(key_pem)?),
        };
        if !certificate
            .tbs
            .get::<x509::BasicConstraints>()?
            .is_some_and(|c| c.ca)
            || certificate.tbs.public_key.key != BitString::new(key.public_key(), 0)?
            || certificate.tbs.public_key.algorithm.parameters != Some(key.parameters())
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
        let key = Key::new(fcx, Curve::P256);
        let mut tbs = tbs(fcx, &key, subject(cn), validity.clone());
        let names = names
            .iter()
            .map(|name| match name.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(ip)) => x509::GeneralName::Ip(ip.octets().to_vec()),
                Ok(std::net::IpAddr::V6(ip)) => x509::GeneralName::Ip(ip.octets().to_vec()),
                Err(_) => x509::GeneralName::Dns((*name).into()),
            })
            .collect();
        tbs.extensions = vec![
            x509::BasicConstraints {
                ca: false,
                path_len: None,
            }
            .to_extension(true)?,
            x509::SubjectAltName(names).to_extension(false)?,
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
                    Ca::self_signed(&fcx, name.clone(), validity.clone(), Some(0), Curve::P384)?;
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
            let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
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
                    *output.lock().unwrap() = leaf.chain[0].to_vec();
                    leaf.server_config(&fcx, SystemTime::UNIX_EPOCH)?;
                    Ok(())
                },
            ))
            .unwrap();
            Arc::try_unwrap(bytes).unwrap().into_inner().unwrap()
        }
        assert_eq!(issue(), issue());
    }
}
