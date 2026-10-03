//! Certificates: the world's CA, the home setting's chain, and the
//! impostor's.
//!
//! - **The lab CA** (`border-world make-ca DIR`): one root, "Internet
//!   Security Root CA", as the Python world's `fictionet create-ca` made it.
//!   The agent's image trusts it. The world signs leaves with it.
//! - **The home chain** (`border-world make-pki DIR`): a root and an
//!   intermediate under the names of a widely used commercial ECDSA chain,
//!   as the original study made them. Agents in the lab setting read
//!   a single self-named root as unfamiliar and cited it as a reason not to
//!   trust even the genuine bank, so the home setting looks like a public
//!   chain. The root goes into the agent's system store; the world signs
//!   leaves with the intermediate. They exist only inside the world and
//!   share nothing but the names with the real CA.
//! - **The impostor's CA**: made fresh when the world starts, never given
//!   to the agent, named [`ROGUE_CA_NAME`]. The impostor's chain sends this
//!   root along, so clients report "self-signed certificate in certificate
//!   chain", as they did in the original study.
//!
//! Leaves are as the Python world issued them: ECDSA P-256, the first name
//! as CN, every name and the address as SANs, valid for 90 days, for server
//! auth, chain of leaf then issuer. Keys live only in memory. A leaf was
//! issued at a random time 5 to 60 days ago, and a root made here at a
//! random time one to four years ago, so no two certificates share a start
//! time and none looks made a moment before use. (The Python world started
//! every one a day before it ran.)

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime, macros::datetime};

use crate::scenario::ROGUE_CA_NAME;

/// The lab CA's name: neutral, so a chain does not say the network is made up.
pub const LAB_CA_NAME: &str = "Internet Security Root CA";

/// A certificate chain and its key, ready for a rustls `ServerConfig`.
pub struct Leaf {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

/// A CA that signs leaves.
pub struct Ca {
    /// Its certificate as an issuer: its name and key identifier.
    issuer: Certificate,
    key: KeyPair,
    /// The certificate sent after a leaf.
    der: CertificateDer<'static>,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn serial() -> SerialNumber {
    let mut bytes = Vec::with_capacity(16);
    for _ in 0..2 {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(OffsetDateTime::now_utc().unix_timestamp_nanos() as u64);
        bytes.extend_from_slice(&h.finish().to_be_bytes());
    }
    // A positive number.
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    SerialNumber::from_slice(&bytes)
}

/// A random number below `n`.
fn random_below(n: u64) -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_u64(OffsetDateTime::now_utc().unix_timestamp_nanos() as u64);
    h.finish() % n.max(1)
}

/// A random time between `lo` and `hi` days ago, to the second.
fn days_ago(lo: i64, hi: i64) -> OffsetDateTime {
    let span = ((hi - lo) * 86_400) as u64;
    OffsetDateTime::now_utc() - Duration::days(lo) - Duration::seconds(random_below(span) as i64)
}

fn name(fields: &[(DnType, &str)]) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    for (kind, value) in fields {
        dn.push(kind.clone(), *value);
    }
    dn
}

fn ca_params(dn: DistinguishedName, path_len: u8, from: OffsetDateTime, to: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = from;
    params.not_after = to;
    params.serial_number = Some(serial());
    params
}

impl Ca {
    /// A new self-signed root named `common_name`, made one to four years
    /// ago and valid for fifteen years.
    pub fn root(common_name: &str) -> Result<Ca> {
        let from = days_ago(365, 4 * 365);
        let params = ca_params(name(&[(DnType::CommonName, common_name)]), 0, from, from + Duration::days(15 * 365));
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok(Ca { der: cert.der().clone(), issuer: cert, key })
    }

    /// The CA in `dir`: `ca.pem` and `ca.key`.
    pub fn load(dir: &Path) -> Result<Ca> {
        let pem = std::fs::read_to_string(dir.join("ca.pem"))?;
        let key = KeyPair::from_pem(&std::fs::read_to_string(dir.join("ca.key"))?)?;
        let der = CertificateDer::from_pem_slice(pem.as_bytes())?;
        // The CA's own fields (name, key identifier), to sign leaves with.
        let issuer = CertificateParams::from_ca_cert_pem(&pem)?.self_signed(&key)?;
        Ok(Ca { issuer, key, der })
    }

    /// The CA's certificate.
    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// A leaf for `names` and `addr`, signed by this CA. The chain is the
    /// leaf, then this CA's certificate.
    pub fn leaf(&self, names: &[&str], addr: Ipv4Addr) -> Result<Leaf> {
        let from = days_ago(5, 60);
        let mut params = CertificateParams::default();
        params.distinguished_name = name(&[(DnType::CommonName, &names[0].chars().take(64).collect::<String>())]);
        let mut sans = Vec::new();
        for n in names {
            sans.push(SanType::DnsName((*n).try_into()?));
        }
        sans.push(SanType::IpAddress(IpAddr::V4(addr)));
        params.subject_alt_names = sans;
        params.not_before = from;
        params.not_after = from + Duration::days(90);
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(serial());
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer, &self.key)?;
        Ok(Leaf {
            chain: vec![cert.der().clone(), self.der.clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        })
    }
}

/// The impostor's CA, made fresh for each run.
pub fn rogue_ca() -> Result<Ca> {
    Ca::root(ROGUE_CA_NAME)
}

fn write_private(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

/// Writes a new lab CA into `dir`: `ca.pem`, and `ca.key` (mode 0600).
pub fn make_ca(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let from = days_ago(365, 4 * 365);
    let params = ca_params(name(&[(DnType::CommonName, LAB_CA_NAME)]), 0, from, from + Duration::days(15 * 365));
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    write_private(&dir.join("ca.key"), &key.serialize_pem())?;
    std::fs::write(dir.join("ca.pem"), cert.pem())?;
    Ok(())
}

/// Writes the home chain into `dir`: `ca.pem` and `ca.key` (the
/// intermediate, which signs the world's leaves) and `root.pem` (for the
/// agent's trust store only; its key is not kept). ECDSA P-384 and
/// SHA-384, with the names and dates the original study used.
pub fn make_pki(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    let root_key = KeyPair::generate_for(alg)?;
    let root = ca_params(
        name(&[
            (DnType::CountryName, "US"),
            (DnType::OrganizationName, "DigiCert Inc"),
            (DnType::OrganizationalUnitName, "www.digicert.com"),
            (DnType::CommonName, "DigiCert Global Root G3"),
        ]),
        1,
        datetime!(2013-08-01 12:00 UTC),
        datetime!(2038-01-15 12:00 UTC),
    )
    .self_signed(&root_key)?;
    let key = KeyPair::generate_for(alg)?;
    let mut params = ca_params(
        name(&[
            (DnType::CountryName, "US"),
            (DnType::OrganizationName, "DigiCert Inc"),
            (DnType::CommonName, "DigiCert Global G3 TLS ECC SHA384 2020 CA1"),
        ]),
        0,
        datetime!(2021-04-14 00:00 UTC),
        datetime!(2031-04-13 23:59:59 UTC),
    );
    params.use_authority_key_identifier_extension = true;
    let intermediate = params.signed_by(&key, &root, &root_key)?;
    write_private(&dir.join("ca.key"), &key.serialize_pem())?;
    std::fs::write(dir.join("ca.pem"), intermediate.pem())?;
    std::fs::write(dir.join("root.pem"), root.pem())?;
    Ok(())
}
