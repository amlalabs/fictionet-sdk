//! A look-alike Zscaler TLS-inspection chain for the desktop world.
//!
//! The guest installs a local root. Each site presents a leaf, the
//! short-lived issuing CA, and the long-lived intermediate CA.
//! [`zscaler`] generates the CA keys from the run seed. Only the public
//! field layout matches Zscaler. All keys and signatures are generated here.

use std::sync::Arc;
use std::time::SystemTime;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::asn1::StringKind::{Ia5, Printable, Utf8};
use fictionet::stdlib::protocols::asn1::{Oid, StringKind};
use fictionet::stdlib::protocols::x509::{self, ExtensionValue, GeneralName, KeyUsage, oid};
use fictionet::stdlib::services::ca::{KeyKind, Leaf, SigningKey};
use fictionet::stdlib::services::tls;
use fictionet::{Cx, Error, Result};
use rustls::pki_types::CertificateDer;

/// The cloud name embedded in the intermediate common names.
pub const DEFAULT_CLOUD: &str = "zscalertwo.net";

/// A day, in seconds.
const DAY: i64 = 86_400;

/// The root's validity, from the 2025 reissue.
const ROOT_NOT_BEFORE: i64 = 1_738_514_300;
const ROOT_NOT_AFTER: i64 = 2_602_514_300;
/// The long-lived intermediate's window: wide, 2024 to 2039.
const INT_NOT_BEFORE: i64 = 1_704_067_200;
const INT_NOT_AFTER: i64 = 2_177_452_800;

/// A built chain of Zscaler-shaped CAs, which issues per-site leaves.
pub struct Zscaler {
    root_pem: String,
    /// The short-lived "(t)" issuing CA's key, which signs every leaf.
    issuing_key: SigningKey,
    /// The "(t)" CA's subject, which becomes each leaf's issuer.
    issuing_subject: x509::Name,
    /// The "(t)" CA's key identifier, which becomes each leaf's authority
    /// key identifier.
    issuing_key_id: Vec<u8>,
    /// What the world sends below the leaf in every handshake: the "(t)"
    /// issuing CA, then the long-lived intermediate.
    intermediates: Vec<CertificateDer<'static>>,
}

/// Builds the root, the long-lived intermediate and the short-lived "(t)"
/// issuing CA for `cloud` (for example [`DEFAULT_CLOUD`]), with fresh RSA
/// 2048 keys from `fcx`. `now_unix` is the run's wall-clock time in Unix
/// seconds. The "(t)" CA's two-week window straddles it.
pub fn zscaler(fcx: &Cx, cloud: &str, now_unix: i64) -> Result<Zscaler> {
    zscaler_since(fcx, cloud, now_unix, now_unix)
}

/// [`zscaler`] for a run whose clock may also read as early as
/// `earliest_unix`: the "(t)" CA's window opens three days before that.
pub fn zscaler_since(fcx: &Cx, cloud: &str, earliest_unix: i64, now_unix: i64) -> Result<Zscaler> {
    let root_validity = validity(ROOT_NOT_BEFORE, ROOT_NOT_AFTER)?;
    let int_validity = validity(INT_NOT_BEFORE, INT_NOT_AFTER)?;
    let issuing_validity = validity(
        earliest_unix.min(now_unix).saturating_sub(3 * DAY),
        now_unix.saturating_add(11 * DAY),
    )?;
    // The root uses PrintableString except for its IA5String email.
    let root_dn = dn(&[
        (oid::COUNTRY, Printable, "US"),
        (oid::STATE, Printable, "California"),
        (oid::LOCALITY, Printable, "San Jose"),
        (oid::ORGANIZATION, Printable, "Zscaler Inc."),
        (oid::ORGANIZATIONAL_UNIT, Printable, "Zscaler Inc."),
        (oid::COMMON_NAME, Printable, "Zscaler Root CA"),
        (oid::EMAIL_ADDRESS, Ia5, "support@zscaler.com"),
    ]);
    // The intermediate has no locality and keeps the mailto: email prefix.
    let int_cn = format!("Zscaler Intermediate Root CA ({cloud})");
    let int_dn = dn(&[
        (oid::COUNTRY, Printable, "US"),
        (oid::STATE, Printable, "California"),
        (oid::ORGANIZATION, Printable, "Zscaler Inc."),
        (oid::ORGANIZATIONAL_UNIT, Printable, "Zscaler Inc."),
        (oid::COMMON_NAME, Printable, &int_cn),
        (oid::EMAIL_ADDRESS, Ia5, "mailto:support@zscaler.com"),
    ]);
    // The issuing CA has no locality or email.
    let issuing_cn = format!("{int_cn} (t)");
    let issuing_dn = dn(&[
        (oid::COUNTRY, Printable, "US"),
        (oid::STATE, Printable, "California"),
        (oid::ORGANIZATION, Printable, "Zscaler Inc."),
        (oid::ORGANIZATIONAL_UNIT, Printable, "Zscaler Inc."),
        (oid::COMMON_NAME, Printable, &issuing_cn),
    ]);

    let root_key = SigningKey::generate(fcx, KeyKind::Rsa2048);
    let int_key = SigningKey::generate(fcx, KeyKind::Rsa2048);
    let issuing_key = SigningKey::generate(fcx, KeyKind::Rsa2048);

    let root_key_id = root_key.key_identifier();
    let root_serial = serial(fcx, true);
    let root = certificate(
        &root_key,
        &root_key,
        root_dn.clone(),
        root_dn.clone(),
        root_validity,
        root_serial.clone(),
        vec![
            x509::SubjectKeyIdentifier(root_key_id.clone()).to_extension(false)?,
            x509::BasicConstraints {
                ca: true,
                path_len: None,
            }
            .to_extension(true)?,
            x509::AuthorityKeyIdentifier {
                key_id: Some(root_key_id.clone()),
                issuer: Some(vec![GeneralName::Directory(root_dn.clone())]),
                serial: Some(root_serial),
            }
            .to_extension(false)?,
            KeyUsage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
                .to_extension(true)?,
        ],
    )?;

    let int_key_id = int_key.key_identifier();
    let int = certificate(
        &int_key,
        &root_key,
        int_dn.clone(),
        root_dn,
        int_validity,
        serial(fcx, false),
        ca_extensions(&int_key_id, &root_key_id)?,
    )?;

    let issuing_key_id = issuing_key.key_identifier();
    let issuing = certificate(
        &issuing_key,
        &int_key,
        issuing_dn.clone(),
        int_dn,
        issuing_validity,
        serial(fcx, false),
        ca_extensions(&issuing_key_id, &int_key_id)?,
    )?;

    Ok(Zscaler {
        root_pem: pem(&root)?,
        issuing_key,
        issuing_subject: issuing_dn,
        issuing_key_id,
        intermediates: vec![issuing.to_bytes()?.into(), int.to_bytes()?.into()],
    })
}

impl Zscaler {
    /// The root certificate as PEM, for the guest to install as its trust
    /// anchor (the world's `zscaler.crt`).
    pub fn root_pem(&self) -> &str {
        &self.root_pem
    }

    /// Mints a leaf for `names`, the site's SANs, signed by the "(t)" issuing CA.
    /// Returns the leaf's private key and the chain the world presents in a
    /// handshake: the leaf, then both intermediate CAs, without the root.
    /// The leaf's window straddles `now_unix`. The first name is the common
    /// name, cut to 64 characters.
    pub fn issue(&self, fcx: &Cx, names: &[&str], now_unix: i64) -> Result<Leaf> {
        self.issue_since(fcx, names, now_unix, now_unix)
    }

    /// [`issue`](Self::issue) for a run whose clock may also read as early
    /// as `earliest_unix`: the leaf's window opens a day before that.
    pub fn issue_since(
        &self,
        fcx: &Cx,
        names: &[&str],
        earliest_unix: i64,
        now_unix: i64,
    ) -> Result<Leaf> {
        let validity = validity(
            earliest_unix.min(now_unix).saturating_sub(DAY),
            now_unix.saturating_add(395 * DAY),
        )?;
        let sans = x509::SubjectAltName(
            names
                .iter()
                .map(|name| GeneralName::from_host(name))
                .collect(),
        );
        let cn = names
            .first()
            .ok_or_else(|| Error::msg("a leaf needs at least one name"))?;
        let cn = cn.chars().take(64).collect::<String>();
        // Wildcards need UTF8String rather than PrintableString.
        let subject = dn(&[
            (oid::COMMON_NAME, Utf8, &cn),
            (oid::ORGANIZATION, Printable, "Zscaler Inc."),
            (oid::ORGANIZATIONAL_UNIT, Printable, "Zscaler Inc."),
        ]);
        let leaf_key = SigningKey::generate(fcx, KeyKind::Rsa2048);
        // No basic constraints, SCT, AIA, or CRL distribution points.
        let leaf = certificate(
            &leaf_key,
            &self.issuing_key,
            subject,
            self.issuing_subject.clone(),
            validity.clone(),
            serial(fcx, false),
            vec![
                KeyUsage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_ENCIPHERMENT)
                    .to_extension(true)?,
                x509::ExtendedKeyUsage(vec![object_id(oid::SERVER_AUTH)]).to_extension(false)?,
                sans.to_extension(false)?,
                x509::SubjectKeyIdentifier(leaf_key.key_identifier()).to_extension(false)?,
                x509::AuthorityKeyIdentifier {
                    key_id: Some(self.issuing_key_id.clone()),
                    issuer: None,
                    serial: None,
                }
                .to_extension(false)?,
            ],
        )?;
        let mut chain = vec![leaf.to_bytes()?.into()];
        chain.extend(self.intermediates.iter().cloned());
        Ok(Leaf {
            chain,
            key: leaf_key.private_key_der()?.into(),
            validity,
        })
    }

    /// A rustls server configuration for a site at `names`: the chain from
    /// [`issue`](Self::issue) and its key, with the run's clock for
    /// validity checks.
    pub fn server_config(
        &self,
        fcx: &Cx,
        names: &[&str],
        now: SystemTime,
    ) -> Result<Arc<tls::ServerConfig>> {
        let now_unix = i64::try_from(now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs())?;
        self.issue(fcx, names, now_unix)?.server_config(fcx, now)
    }
}

/// The extensions shared by both intermediate CAs.
fn ca_extensions(key_id: &[u8], parent_key_id: &[u8]) -> Result<Vec<x509::Extension>> {
    Ok(vec![
        x509::BasicConstraints {
            ca: true,
            path_len: None,
        }
        .to_extension(true)?,
        KeyUsage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
            .to_extension(true)?,
        x509::SubjectKeyIdentifier(key_id.to_vec()).to_extension(false)?,
        x509::AuthorityKeyIdentifier {
            key_id: Some(parent_key_id.to_vec()),
            issuer: None,
            serial: None,
        }
        .to_extension(false)?,
    ])
}

/// Assembles a certificate: `subject_key`'s public key, signed by `signer`,
/// with the caller's subject, issuer, validity, serial and extensions.
fn certificate(
    subject_key: &SigningKey,
    signer: &SigningKey,
    subject: x509::Name,
    issuer: x509::Name,
    validity: x509::Validity,
    serial: Vec<u8>,
    extensions: Vec<x509::Extension>,
) -> Result<x509::Certificate> {
    signer.sign(x509::TbsCertificate {
        version: x509::Version::V3,
        serial,
        signature: signer.algorithm(),
        issuer,
        validity,
        subject,
        public_key: subject_key.public_key_info(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions,
    })
}

/// A distinguished name from attributes, in order.
fn dn(attributes: &[(&[u8], StringKind, &str)]) -> x509::Name {
    let mut name = x509::Name::default();
    for &(oid, kind, text) in attributes {
        name.push(
            object_id(oid),
            x509::Value::Text {
                kind,
                text: text.to_string(),
            },
        );
    }
    name
}

/// A serial number from the run's randomness. With `high_bit`, an eight-byte
/// value with its top bit set, so it renders as sixteen hex digits with a
/// leading zero byte, like the real root's. Otherwise a positive, nonzero,
/// minimally encoded eight-byte value.
fn serial(fcx: &Cx, high_bit: bool) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    fcx.fill_random(&mut bytes);
    if high_bit {
        bytes[0] |= 0x80;
        let mut serial = Vec::with_capacity(9);
        serial.push(0x00);
        serial.extend_from_slice(&bytes);
        serial
    } else {
        bytes[0] = (bytes[0] & 0x7f) | 1;
        bytes.to_vec()
    }
}

fn validity(not_before: i64, not_after: i64) -> Result<x509::Validity> {
    Ok(x509::Validity {
        not_before: x509::Time::from_unix(not_before)?,
        not_after: x509::Time::from_unix(not_after)?,
    })
}

fn object_id(bytes: &[u8]) -> Oid {
    Oid::from_contents(bytes).expect("a known object identifier")
}

fn pem(cert: &x509::Certificate) -> Result<String> {
    Ok(String::from_utf8(
        x509::PemBlock::new("CERTIFICATE", cert)?.to_bytes()?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::protocols::asn1::{Reader, Rules};
    use x509::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier, Time, Version};

    /// The SCT (signed certificate timestamp) extension, 1.3.6.1.4.1.11129.2.4.2.
    const SCT: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

    fn verifier(root: &CertificateDer<'static>) -> Arc<rustls::client::WebPkiServerVerifier> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.clone()).unwrap();
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap()
    }

    #[test]
    fn a_client_that_trusts_only_the_root_validates_a_reissued_leaf() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(7),
            |fcx| async move {
                let now = 1_800_000_000;
                let z = zscaler(&fcx, DEFAULT_CLOUD, now)?;
                let Leaf { chain, .. } =
                    z.issue(&fcx, &["example.test", "www.example.test"], now)?;
                let root = x509::Certificate::from_pem(z.root_pem().as_bytes())?;
                let verifier = verifier(&root.to_bytes()?.into());
                let at = rustls::pki_types::UnixTime::since_unix_epoch(
                    std::time::Duration::from_secs(now as u64),
                );
                use rustls::client::danger::ServerCertVerifier;
                let verify = |name: &'static str, intermediates: &[CertificateDer<'static>]| {
                    verifier.verify_server_cert(
                        &chain[0],
                        intermediates,
                        &name.try_into().unwrap(),
                        &[],
                        at,
                    )
                };
                // The leaf validates for its name only with both
                // intermediates present, since the client trusts the root
                // alone.
                verify("example.test", &chain[1..])?;
                assert!(verify("www.example.test", &chain[1..]).is_ok());
                assert!(verify("other.test", &chain[1..]).is_err());
                assert!(verify("example.test", &[]).is_err());
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn extreme_dates_return_errors() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(11),
            |fcx| async move {
                let z = zscaler(&fcx, DEFAULT_CLOUD, 1_800_000_000)?;
                for now in [i64::MIN, i64::MAX] {
                    assert!(zscaler(&fcx, DEFAULT_CLOUD, now).is_err());
                    assert!(z.issue(&fcx, &["example.test"], now).is_err());
                }
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn long_leaf_names_keep_the_full_san() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(11),
            |fcx| async move {
                let now = 1_800_000_000;
                let z = zscaler(&fcx, DEFAULT_CLOUD, now)?;
                let name = format!("{}.test", "a".repeat(60));
                let leaf = z.issue(&fcx, &[&name], now)?;
                let cert = x509::Certificate::parse(&leaf.chain[0])?;
                assert_eq!(cert.tbs.subject.common_name(), Some(&name[..64]));
                assert_eq!(
                    cert.tbs.get::<x509::SubjectAltName>()?,
                    Some(x509::SubjectAltName(vec![GeneralName::Dns(name)]))
                );
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn chains_and_keys_follow_the_seed() {
        fn run(seed: u64) -> Vec<Vec<u8>> {
            let bytes = Arc::new(fictionet::sync::Mutex::new(Vec::new()));
            let output = bytes.clone();
            fictionet::block_on(fictionet::lab(
                fictionet::Seed::from_u64(seed),
                move |fcx| async move {
                    let z = zscaler(&fcx, DEFAULT_CLOUD, 1_800_000_000)?;
                    let Leaf { chain, key, .. } =
                        z.issue(&fcx, &["example.test"], 1_800_000_000)?;
                    let mut result =
                        vec![x509::Certificate::from_pem(z.root_pem().as_bytes())?.to_bytes()?];
                    result.extend(chain.iter().map(|c| c.to_vec()));
                    result.push(key.secret_der().to_vec());
                    *output.lock() = result;
                    Ok(())
                },
            ))
            .unwrap();
            std::mem::take(Arc::try_unwrap(bytes).unwrap().get_mut())
        }
        let first = run(11);
        assert_eq!(first, run(11));
        let other = run(12);
        assert_eq!(first.len(), 5);
        assert_eq!(other.len(), first.len());
        for (i, (a, b)) in first.iter().zip(other).enumerate() {
            assert_ne!(a, &b);
            if i < 4 {
                assert_ne!(
                    x509::Certificate::parse(a).unwrap().tbs.public_key,
                    x509::Certificate::parse(&b).unwrap().tbs.public_key
                );
            }
        }
    }

    fn parsed_chain(seed: u64) -> [x509::Certificate; 4] {
        let certificates = Arc::new(fictionet::sync::Mutex::new(None));
        let output = certificates.clone();
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(seed),
            move |fcx| async move {
                let now = 1_800_000_000;
                let z = zscaler(&fcx, DEFAULT_CLOUD, now)?;
                let Leaf { chain, key, .. } = z.issue(
                    &fcx,
                    &["*.example.test", "example.test", "192.0.2.1", "2001:db8::1"],
                    now,
                )?;
                assert_eq!(chain.len(), 3);
                let root = x509::Certificate::from_pem(z.root_pem().as_bytes())?;
                assert_eq!(pem(&root)?, z.root_pem());
                let int = x509::Certificate::parse(&chain[2])?;
                let issuing = x509::Certificate::parse(&chain[1])?;
                let leaf = x509::Certificate::parse(&chain[0])?;
                tls::config_builder(&fcx, SystemTime::UNIX_EPOCH)
                    .with_safe_default_protocol_versions()?
                    .with_no_client_auth()
                    .with_single_cert(chain, key)?;
                *output.lock() = Some([root, int, issuing, leaf]);
                Ok(())
            },
        ))
        .unwrap();
        Arc::try_unwrap(certificates)
            .unwrap()
            .get_mut()
            .take()
            .unwrap()
    }

    #[test]
    fn names_match_the_zscaler_layout() -> Result {
        let [root, int, issuing, leaf] = parsed_chain(11);
        // The published root's subject DER contains only its public name fields.
        let root_name = b"\x30\x81\xa1\x31\x0b\x30\x09\x06\x03U\x04\x06\x13\x02US\
            \x31\x13\x30\x11\x06\x03U\x04\x08\x13\x0aCalifornia\
            \x31\x11\x30\x0f\x06\x03U\x04\x07\x13\x08San Jose\
            \x31\x15\x30\x13\x06\x03U\x04\x0a\x13\x0cZscaler Inc.\
            \x31\x15\x30\x13\x06\x03U\x04\x0b\x13\x0cZscaler Inc.\
            \x31\x18\x30\x16\x06\x03U\x04\x03\x13\x0fZscaler Root CA\
            \x31\x22\x30\x20\x06\x09\x2a\x86H\x86\xf7\x0d\x01\x09\x01\x16\x13\
            support@zscaler.com";
        assert_eq!(root.tbs.subject.to_bytes()?, root_name);
        let expected_name = |attributes: &[(&[u8], StringKind, &str)]| x509::Name {
            rdns: attributes
                .iter()
                .map(|&(id, kind, text)| {
                    vec![x509::Attribute {
                        oid: Oid::from_contents(id).unwrap(),
                        value: x509::Value::Text {
                            kind,
                            text: text.into(),
                        },
                    }]
                })
                .collect(),
        };
        assert_eq!(
            int.tbs.subject,
            expected_name(&[
                (oid::COUNTRY, Printable, "US"),
                (oid::STATE, Printable, "California"),
                (oid::ORGANIZATION, Printable, "Zscaler Inc."),
                (oid::ORGANIZATIONAL_UNIT, Printable, "Zscaler Inc."),
                (
                    oid::COMMON_NAME,
                    Printable,
                    "Zscaler Intermediate Root CA (zscalertwo.net)"
                ),
                (oid::EMAIL_ADDRESS, Ia5, "mailto:support@zscaler.com"),
            ])
        );
        assert_eq!(
            issuing.tbs.subject,
            expected_name(&[
                (oid::COUNTRY, Printable, "US"),
                (oid::STATE, Printable, "California"),
                (oid::ORGANIZATION, Printable, "Zscaler Inc."),
                (oid::ORGANIZATIONAL_UNIT, Printable, "Zscaler Inc."),
                (
                    oid::COMMON_NAME,
                    Printable,
                    "Zscaler Intermediate Root CA (zscalertwo.net) (t)"
                ),
            ])
        );
        assert_eq!(
            leaf.tbs.subject,
            expected_name(&[
                (oid::COMMON_NAME, Utf8, "*.example.test"),
                (oid::ORGANIZATION, Printable, "Zscaler Inc."),
                (oid::ORGANIZATIONAL_UNIT, Printable, "Zscaler Inc."),
            ])
        );
        for (cert, issuer) in [
            (&root, &root),
            (&int, &root),
            (&issuing, &int),
            (&leaf, &issuing),
        ] {
            assert_eq!(cert.tbs.issuer, issuer.tbs.subject);
            assert_eq!(cert.tbs.issuer_unique_id, None);
            assert_eq!(cert.tbs.subject_unique_id, None);
        }
        Ok(())
    }

    #[test]
    fn validity_matches_the_zscaler_layout() -> Result {
        let [root, int, issuing, leaf] = parsed_chain(11);
        assert_eq!(
            root.tbs.validity,
            x509::Validity {
                not_before: Time::Utc("250202163820Z".into()),
                not_after: Time::Generalized("20520620163820Z".into()),
            }
        );
        assert_eq!(
            int.tbs.validity,
            x509::Validity {
                not_before: Time::Utc("240101000000Z".into()),
                not_after: Time::Utc("390101000000Z".into()),
            }
        );
        assert_eq!(
            issuing.tbs.validity,
            x509::Validity {
                not_before: Time::Utc("270112080000Z".into()),
                not_after: Time::Utc("270126080000Z".into()),
            }
        );
        assert_eq!(
            leaf.tbs.validity,
            x509::Validity {
                not_before: Time::Utc("270114080000Z".into()),
                not_after: Time::Utc("280214080000Z".into()),
            }
        );
        Ok(())
    }

    #[test]
    fn keys_and_signatures_match_the_zscaler_layout() -> Result {
        let [root, int, issuing, leaf] = parsed_chain(11);
        assert_eq!(root.tbs.serial.len(), 9);
        assert_eq!(root.tbs.serial[0], 0);
        assert_ne!(root.tbs.serial[1] & 0x80, 0);
        let signature_algorithm = x509::AlgorithmIdentifier {
            oid: object_id(oid::SHA256_WITH_RSA),
            parameters: Some(vec![5, 0]),
        };
        let public_key_algorithm = x509::AlgorithmIdentifier {
            oid: object_id(oid::RSA_ENCRYPTION),
            parameters: Some(vec![5, 0]),
        };
        for (cert, issuer) in [
            (&root, &root),
            (&int, &root),
            (&issuing, &int),
            (&leaf, &issuing),
        ] {
            let tbs = &cert.tbs;
            assert_eq!(tbs.version, Version::V3);
            assert_eq!(tbs.signature, signature_algorithm);
            assert_eq!(cert.signature_algorithm, signature_algorithm);
            assert_eq!(tbs.public_key.algorithm, public_key_algorithm);
            assert_eq!(tbs.public_key.key.unused(), 0);
            assert_eq!(tbs.public_key.key.bytes().len(), 270);
            let mut r = Reader::new(tbs.public_key.key.bytes(), Rules::Der);
            let mut rsa = r.read_sequence()?;
            let n = rsa.read_integer()?;
            assert_eq!(n.as_bytes().len(), 257);
            assert_eq!(n.as_bytes()[0], 0);
            assert_ne!(n.as_bytes()[1] & 0x80, 0);
            assert_eq!(rsa.read_u64()?, 65_537);
            rsa.finish()?;
            r.finish()?;
            assert_eq!(cert.signature.unused(), 0);
            assert_eq!(cert.signature.bytes().len(), 256);
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                issuer.tbs.public_key.key.bytes(),
            )
            .verify(&cert.tbs_der, cert.signature.bytes())
            .unwrap();
            if cert != &root {
                assert_eq!(tbs.serial.len(), 8);
                assert!((1..=0x7f).contains(&tbs.serial[0]));
            }
        }
        Ok(())
    }

    #[test]
    fn extensions_match_the_zscaler_layout() -> Result {
        let [root, int, issuing, leaf] = parsed_chain(11);
        let mut root_authority = vec![0x30, 0x81, 0xcb, 0x80, 0x14];
        root_authority.extend(root.tbs.get::<SubjectKeyIdentifier>()?.unwrap().0);
        root_authority.extend([0xa1, 0x81, 0xa7, 0xa4, 0x81, 0xa4]);
        root_authority.extend(root.tbs.subject.to_bytes()?);
        root_authority.extend([0x82, 9]);
        root_authority.extend(&root.tbs.serial);
        assert_eq!(
            root.tbs
                .extension(oid::AUTHORITY_KEY_IDENTIFIER)
                .unwrap()
                .value,
            root_authority
        );
        let ski =
            |cert: &x509::Certificate| cert.tbs.get::<SubjectKeyIdentifier>().unwrap().unwrap().0;
        for (cert, issuer) in [
            (&root, &root),
            (&int, &root),
            (&issuing, &int),
            (&leaf, &issuing),
        ] {
            let tbs = &cert.tbs;
            assert_eq!(
                ski(cert),
                ring::digest::digest(
                    &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
                    tbs.public_key.key.bytes(),
                )
                .as_ref()
            );
            let aki = AuthorityKeyIdentifier {
                key_id: Some(ski(issuer)),
                issuer: (cert == &root)
                    .then(|| vec![GeneralName::Directory(root.tbs.subject.clone())]),
                serial: (cert == &root).then(|| root.tbs.serial.clone()),
            };
            assert_eq!(tbs.get::<AuthorityKeyIdentifier>()?, Some(aki.clone()));
            let own_ski = SubjectKeyIdentifier(ski(cert)).to_extension(false)?;
            let authority = aki.to_extension(false)?;
            let bc = BasicConstraints {
                ca: true,
                path_len: None,
            }
            .to_extension(true)?;
            assert_eq!(bc.value, [0x30, 3, 1, 1, 0xff]);
            let ca_ku = x509::Extension {
                oid: object_id(oid::KEY_USAGE),
                critical: true,
                value: vec![3, 2, 1, 0x86],
            };
            let expected = if cert == &root {
                vec![own_ski, bc, authority, ca_ku]
            } else if cert != &leaf {
                vec![bc, ca_ku, own_ski, authority]
            } else {
                vec![
                    x509::Extension {
                        oid: object_id(oid::KEY_USAGE),
                        critical: true,
                        value: vec![3, 2, 5, 0xa0],
                    },
                    x509::ExtendedKeyUsage(vec![object_id(oid::SERVER_AUTH)])
                        .to_extension(false)?,
                    x509::SubjectAltName(vec![
                        GeneralName::Dns("*.example.test".into()),
                        GeneralName::Dns("example.test".into()),
                        GeneralName::Ip(vec![192, 0, 2, 1]),
                        GeneralName::Ip(vec![
                            0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        ]),
                    ])
                    .to_extension(false)?,
                    own_ski,
                    authority,
                ]
            };
            assert_eq!(tbs.extensions, expected);
        }
        assert!(leaf.tbs.extension(SCT).is_none());
        assert!(leaf.tbs.extension(oid::AUTHORITY_INFO_ACCESS).is_none());
        assert!(leaf.tbs.extension(oid::CRL_DISTRIBUTION_POINTS).is_none());
        assert!(leaf.tbs.extension(oid::BASIC_CONSTRAINTS).is_none());
        Ok(())
    }
}
