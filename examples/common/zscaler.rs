//! A look-alike Zscaler TLS-inspection chain for the desktop world.
//!
//! A real enterprise running Zscaler intercepts TLS: the client trusts a
//! locally installed "Zscaler Root CA", and every site it visits is
//! re-signed on the fly, so the browser sees a four-level chain ending in
//! that root instead of the site's real certificate. A sandboxed desktop
//! that trusts this root sees the same familiar chain, not an obvious
//! one-off synthetic certificate.
//!
//! [`zscaler`] builds the three CAs once (root, a long-lived intermediate,
//! and the short-lived "(t)" issuing CA). [`Zscaler::server_config`] then
//! mints a leaf per site, re-signed by the "(t)" CA, and hands back the
//! chain the world presents in every handshake: the leaf and both
//! intermediates, never the root. The guest trusts only the root, as
//! [`Zscaler::root_pem`] gives it.
//!
//! Nothing here is Zscaler's: fresh RSA keys are generated from the run's
//! seed and the root is self-signed. Only the public, observable field
//! layout of a real deployment is reproduced, from a field map built by
//! parsing the published Zscaler root and real `openssl s_client` captures.
//! The field choices (exact subject names, the `mailto:` quirk on the first
//! intermediate, the `(t)` suffix, criticality, the absence of SCTs, AIA and
//! CRL on the leaf) are what make the chain recognizable.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::asn1::{Oid, StringKind};
use fictionet::stdlib::protocols::x509::{self, ExtensionValue, GeneralName, KeyUsage, oid};
use fictionet::stdlib::services::ca::{KeyKind, SigningKey};
use fictionet::stdlib::services::tls;
use fictionet::{Cx, Error, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The default Zscaler cloud whose name is embedded in the intermediate
/// common names. The observed capture is `zscalertwo.net`; every cloud
/// shares the same root and differs only in this token.
pub const DEFAULT_CLOUD: &str = "zscalertwo.net";

/// A day, in seconds.
const DAY: i64 = 86_400;

/// The root's validity: the 2025 reissue's window (2025-02-02 to
/// 2052-06-20), which contains any plausible run date.
const ROOT_NOT_BEFORE: i64 = 1_738_514_300;
const ROOT_NOT_AFTER: i64 = 2_602_514_300;
/// The long-lived intermediate's window: wide, 2024 to 2039.
const INT_NOT_BEFORE: i64 = 1_704_067_200;
const INT_NOT_AFTER: i64 = 2_177_452_800;

/// A built chain of Zscaler-shaped CAs, which issues per-site leaves.
pub struct Zscaler {
    root_pem: String,
    root_der: CertificateDer<'static>,
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
/// seconds; the "(t)" CA's two-week window straddles it.
pub fn zscaler(fcx: &Cx, cloud: &str, now_unix: i64) -> Result<Zscaler> {
    let root_key = SigningKey::generate(fcx, KeyKind::Rsa2048);
    let int_key = SigningKey::generate(fcx, KeyKind::Rsa2048);
    let issuing_key = SigningKey::generate(fcx, KeyKind::Rsa2048);

    // §1 Root CA. C, ST, L, O, OU, CN, emailAddress; every attribute
    // PrintableString except the IA5String email. O and OU are identical.
    let root_dn = dn(&[
        (oid::COUNTRY, StringKind::Printable, "US"),
        (oid::STATE, StringKind::Printable, "California"),
        (oid::LOCALITY, StringKind::Printable, "San Jose"),
        (oid::ORGANIZATION, StringKind::Printable, "Zscaler Inc."),
        (oid::ORGANIZATIONAL_UNIT, StringKind::Printable, "Zscaler Inc."),
        (oid::COMMON_NAME, StringKind::Printable, "Zscaler Root CA"),
        (oid::EMAIL_ADDRESS, StringKind::Ia5, "support@zscaler.com"),
    ]);
    // §2 Long-lived intermediate (depth 2). No locality; the email keeps
    // the literal `mailto:` prefix seen in the capture.
    let int_cn = format!("Zscaler Intermediate Root CA ({cloud})");
    let int_dn = dn(&[
        (oid::COUNTRY, StringKind::Printable, "US"),
        (oid::STATE, StringKind::Printable, "California"),
        (oid::ORGANIZATION, StringKind::Printable, "Zscaler Inc."),
        (oid::ORGANIZATIONAL_UNIT, StringKind::Printable, "Zscaler Inc."),
        (oid::COMMON_NAME, StringKind::Printable, &int_cn),
        (
            oid::EMAIL_ADDRESS,
            StringKind::Ia5,
            "mailto:support@zscaler.com",
        ),
    ]);
    // §3 Short-lived "(t)" issuing CA (depth 1). No locality, no email; the
    // common name is the intermediate's with " (t)" appended.
    let issuing_cn = format!("{int_cn} (t)");
    let issuing_dn = dn(&[
        (oid::COUNTRY, StringKind::Printable, "US"),
        (oid::STATE, StringKind::Printable, "California"),
        (oid::ORGANIZATION, StringKind::Printable, "Zscaler Inc."),
        (oid::ORGANIZATIONAL_UNIT, StringKind::Printable, "Zscaler Inc."),
        (oid::COMMON_NAME, StringKind::Printable, &issuing_cn),
    ]);

    let root_key_id = root_key.key_identifier();
    let root_serial = serial(fcx, true);
    // The root's authority key identifier carries all three forms: the key
    // id, the issuer's own directory name, and the issuer's serial.
    let root = issue(
        &root_key,
        &root_key,
        root_dn.clone(),
        root_dn.clone(),
        validity(ROOT_NOT_BEFORE, ROOT_NOT_AFTER)?,
        root_serial.clone(),
        vec![
            x509::SubjectKeyIdentifier(root_key_id.clone()).to_extension(false)?,
            x509::BasicConstraints {
                ca: true,
                path_len: None,
            }
            .to_extension(true)?,
            KeyUsage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)
                .to_extension(true)?,
            x509::AuthorityKeyIdentifier {
                key_id: Some(root_key_id.clone()),
                issuer: Some(vec![GeneralName::Directory(root_dn.clone())]),
                serial: Some(root_serial),
            }
            .to_extension(false)?,
        ],
    )?;

    let int_key_id = int_key.key_identifier();
    let int = issue(
        &int_key,
        &root_key,
        int_dn.clone(),
        root_dn,
        validity(INT_NOT_BEFORE, INT_NOT_AFTER)?,
        serial(fcx, false),
        ca_extensions(&int_key_id, &root_key_id)?,
    )?;

    let issuing_key_id = issuing_key.key_identifier();
    // The "(t)" CA is rotated weekly; its ~two-week window straddles now.
    let issuing = issue(
        &issuing_key,
        &int_key,
        issuing_dn.clone(),
        int_dn,
        validity(now_unix - 3 * DAY, now_unix + 11 * DAY)?,
        serial(fcx, false),
        ca_extensions(&issuing_key_id, &int_key_id)?,
    )?;

    Ok(Zscaler {
        root_pem: pem(&root)?,
        root_der: root.to_bytes()?.into(),
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

    /// The root certificate as DER.
    pub fn root_der(&self) -> &CertificateDer<'static> {
        &self.root_der
    }

    /// Mints a leaf for `names` (the site's SANs; the first is the common
    /// name), re-signed by the "(t)" issuing CA, and returns the chain the
    /// world presents in a handshake (leaf, then both intermediate CAs,
    /// never the root) and the leaf's private key. The leaf's window
    /// straddles `now_unix`.
    pub fn issue(
        &self,
        fcx: &Cx,
        names: &[&str],
        now_unix: i64,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let leaf_key = SigningKey::generate(fcx, KeyKind::Rsa2048);
        let cn = names
            .first()
            .ok_or_else(|| Error::msg("a leaf needs at least one name"))?;
        // The leaf's subject carries the origin's host as the common name
        // but Zscaler's own O and OU, and no country, state, locality or
        // email. A wildcard host is not a PrintableString, so the common
        // name is UTF-8.
        let subject = dn(&[
            (oid::COMMON_NAME, StringKind::Utf8, cn),
            (oid::ORGANIZATION, StringKind::Printable, "Zscaler Inc."),
            (oid::ORGANIZATIONAL_UNIT, StringKind::Printable, "Zscaler Inc."),
        ]);
        let sans = names
            .iter()
            .map(|name| match name.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => GeneralName::Ip(ip.octets().to_vec()),
                Ok(IpAddr::V6(ip)) => GeneralName::Ip(ip.octets().to_vec()),
                Err(_) => GeneralName::Dns((*name).to_string()),
            })
            .collect();
        // serverAuth, a server leaf's key usage, the origin's names, and the
        // issuer's key id. No basic constraints (not a CA), and no SCT, AIA
        // or CRL: a re-signed inspection leaf is never logged and carries
        // the whole chain inline.
        let leaf = issue(
            &leaf_key,
            &self.issuing_key,
            subject,
            self.issuing_subject.clone(),
            validity(now_unix - DAY, now_unix + 395 * DAY)?,
            serial(fcx, false),
            vec![
                KeyUsage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_ENCIPHERMENT)
                    .to_extension(true)?,
                x509::ExtendedKeyUsage(vec![object_id(oid::SERVER_AUTH)]).to_extension(false)?,
                x509::SubjectAltName(sans).to_extension(false)?,
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
        Ok((chain, leaf_key.private_key_der()?.into()))
    }

    /// A rustls server configuration for a site at `names`: the chain from
    /// [`issue`](Self::issue) and its key, with the run's clock for
    /// validity checks. `now` and `now_unix` are the same instant.
    pub fn server_config(
        &self,
        fcx: &Cx,
        names: &[&str],
        now: SystemTime,
        now_unix: i64,
    ) -> Result<Arc<tls::ServerConfig>> {
        let (chain, key) = self.issue(fcx, names, now_unix)?;
        Ok(Arc::new(
            tls::config_builder(fcx, now)
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(chain, key)?,
        ))
    }
}

/// The extensions shared by both intermediate CAs: a critical CA basic
/// constraint, a critical key usage for signing certificates and CRLs, this
/// CA's own key id, and the parent's key id as the authority key id.
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
fn issue(
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
            fictionet::RunOptions::new(fictionet::Seed::from_u64(7)),
            |fcx| async move {
                let now = 1_800_000_000;
                let z = zscaler(&fcx, DEFAULT_CLOUD, now)?;
                let (chain, _key) =
                    z.issue(&fcx, &["example.test", "www.example.test"], now)?;

                let verifier = verifier(z.root_der());
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
    fn the_fields_match_the_zscaler_layout() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(11)),
            |fcx| async move {
                let now = 1_800_000_000;
                let z = zscaler(&fcx, DEFAULT_CLOUD, now)?;
                let (chain, _key) = z.issue(&fcx, &["example.test"], now)?;

                let root = x509::Certificate::parse(z.root_der())?;
                // RSA 2048 with a SHA-256 signature.
                assert_eq!(root.signature_algorithm.oid.as_bytes(), oid::SHA256_WITH_RSA);
                assert_eq!(
                    root.tbs.public_key.algorithm.oid.as_bytes(),
                    oid::RSA_ENCRYPTION
                );
                // A 2048-bit RSA public key is a ~270-byte RSAPublicKey.
                assert!((260..=280).contains(&root.tbs.public_key.key.bytes().len()));
                // The serial renders as sixteen hex digits: eight bytes with
                // the top bit set, so a leading zero byte makes it positive.
                assert_eq!(root.tbs.serial.len(), 9);
                assert_eq!(root.tbs.serial[0], 0x00);
                assert!(root.tbs.serial[1] & 0x80 != 0);
                // Self-signed: issuer equals subject, seven attributes in order.
                assert_eq!(root.tbs.issuer, root.tbs.subject);
                assert_eq!(root.tbs.subject.rdns.len(), 7);
                assert_eq!(root.tbs.subject.common_name(), Some("Zscaler Root CA"));
                // The email is an IA5String; the rest are PrintableString.
                match root.tbs.subject.find(oid::EMAIL_ADDRESS) {
                    Some(x509::Value::Text { kind, text }) => {
                        assert_eq!(*kind, StringKind::Ia5);
                        assert_eq!(text, "support@zscaler.com");
                    }
                    other => panic!("unexpected email attribute: {other:?}"),
                }
                match root.tbs.subject.find(oid::COUNTRY) {
                    Some(x509::Value::Text { kind, .. }) => {
                        assert_eq!(*kind, StringKind::Printable)
                    }
                    other => panic!("unexpected country attribute: {other:?}"),
                }
                // Basic constraints critical CA:TRUE; key usage critical.
                let bc = root
                    .tbs
                    .extension(oid::BASIC_CONSTRAINTS)
                    .expect("basic constraints");
                assert!(bc.critical);
                assert!(root.tbs.get::<x509::BasicConstraints>()?.unwrap().ca);
                assert!(
                    root.tbs
                        .extension(oid::KEY_USAGE)
                        .expect("key usage")
                        .critical
                );
                // The root's authority key id carries key id, issuer and serial.
                let aki = root
                    .tbs
                    .get::<x509::AuthorityKeyIdentifier>()?
                    .expect("authority key id");
                assert!(aki.key_id.is_some());
                assert!(aki.issuer.is_some());
                assert_eq!(aki.serial.as_deref(), Some(root.tbs.serial.as_slice()));

                // The first intermediate's common name carries the cloud; the
                // issuing CA appends " (t)".
                let int = x509::Certificate::parse(&chain[2])?;
                let issuing = x509::Certificate::parse(&chain[1])?;
                assert_eq!(
                    int.tbs.subject.common_name(),
                    Some("Zscaler Intermediate Root CA (zscalertwo.net)")
                );
                assert_eq!(
                    issuing.tbs.subject.common_name(),
                    Some("Zscaler Intermediate Root CA (zscalertwo.net) (t)")
                );
                // The first intermediate keeps the mailto: email quirk.
                assert_eq!(
                    int.tbs.subject.find(oid::EMAIL_ADDRESS).and_then(|v| v.as_text()),
                    Some("mailto:support@zscaler.com")
                );

                // The leaf: the origin's name, Zscaler's O and OU, serverAuth,
                // and no SCT, AIA or CRL.
                let leaf = x509::Certificate::parse(&chain[0])?;
                assert_eq!(leaf.tbs.subject.common_name(), Some("example.test"));
                assert_eq!(
                    leaf.tbs.subject.find(oid::ORGANIZATION).and_then(|v| v.as_text()),
                    Some("Zscaler Inc.")
                );
                assert!(
                    leaf.tbs
                        .get::<x509::ExtendedKeyUsage>()?
                        .unwrap()
                        .contains(oid::SERVER_AUTH)
                );
                assert!(leaf.tbs.extension(SCT).is_none());
                assert!(leaf.tbs.extension(oid::AUTHORITY_INFO_ACCESS).is_none());
                assert!(leaf.tbs.extension(oid::CRL_DISTRIBUTION_POINTS).is_none());
                assert!(leaf.tbs.extension(oid::BASIC_CONSTRAINTS).is_none());
                Ok(())
            },
        ))
        .unwrap();
    }
}
