//! The Border world's roots, intermediate, and server certificates.
//!
//! The lab root and the home chain keep the names used by the study.
//! Their P-256 keys come from the run. The home intermediate signs the
//! world's leaves; only its root goes into the agent's trust store.
//! The impostor sends its separate root along with its leaf.
//! Leaves name each DNS name and address, start 5 to 60 days before the
//! host's clock, and last 90 days.

use crate::scenario::ROGUE_CA_NAME;
use fictionet::stdlib::{
    ca::{Ca, Leaf},
    codec::Wire,
    x509::{self, ExtensionValue},
};
use fictionet::{Cx, Result};
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The lab root's common name.
pub const LAB_CA_NAME: &str = "Internet Security Root CA";

/// Loads the issuing certificate and key from a directory.
pub fn load(dir: &Path) -> Result<Ca> {
    Ca::from_pem(
        &std::fs::read_to_string(dir.join("ca.pem"))?,
        &std::fs::read_to_string(dir.join("ca.key"))?,
    )
}

/// Issues a site's names and address with the scenario's validity interval.
pub fn leaf(fcx: &Cx, ca: &Ca, names: &[&str], addr: Ipv4Addr) -> Result<Leaf> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let from = now - 5 * 86400 - (fcx.random_u64() % (55 * 86400)) as i64;
    let address = addr.to_string();
    let names: Vec<_> = names.iter().copied().chain([address.as_str()]).collect();
    ca.issue(
        fcx,
        &names,
        x509::Validity {
            not_before: x509::Time::from_unix(from)?,
            not_after: x509::Time::from_unix(from + 90 * 86400)?,
        },
    )
}

/// Makes the impostor's separate root.
pub fn rogue_ca(fcx: &Cx) -> Result<Ca> {
    Ca::new(fcx, ROGUE_CA_NAME)
}

fn write_ca(dir: &Path, ca: &Ca) -> Result {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join("ca.key"))?;
    file.write_all(ca.key_pem().as_bytes())?;
    std::fs::write(dir.join("ca.pem"), ca.cert_pem())?;
    Ok(())
}

/// Writes a lab root and its private key, with mode 0600, into `dir`.
pub fn make_ca(fcx: &Cx, dir: &Path) -> Result {
    write_ca(dir, &Ca::new(fcx, LAB_CA_NAME)?)
}

fn home_name(common_name: &str, unit: bool) -> x509::Name {
    use fictionet::stdlib::asn1::{Oid, StringKind};
    let mut name = x509::Name::default();
    for (oid, text) in [
        (x509::oid::COUNTRY, "US"),
        (x509::oid::ORGANIZATION, "DigiCert Inc"),
    ]
    .into_iter()
    .chain(unit.then_some((x509::oid::ORGANIZATIONAL_UNIT, "www.digicert.com")))
    .chain([(x509::oid::COMMON_NAME, common_name)])
    {
        name.push(
            Oid::from_contents(oid).unwrap(),
            x509::Value::Text {
                kind: StringKind::Utf8,
                text: text.into(),
            },
        );
    }
    name
}

/// Writes the home root and intermediate with the study's names and dates.
/// The intermediate key is retained; the root key is discarded.
pub fn make_pki(fcx: &Cx, dir: &Path) -> Result {
    let root = Ca::new(fcx, "DigiCert Global Root G3")?;
    let mut tbs = x509::Certificate::parse(&root.cert_der())?.tbs;
    tbs.validity = x509::Validity {
        not_before: x509::Time::from_unix(1375358400)?,
        not_after: x509::Time::from_unix(2147169600)?,
    };
    tbs.subject = home_name("DigiCert Global Root G3", true);
    tbs.extensions
        .retain(|e| e.oid.as_bytes() != x509::oid::BASIC_CONSTRAINTS);
    tbs.extensions.push(
        x509::BasicConstraints {
            ca: true,
            path_len: Some(1),
        }
        .to_extension(true)?,
    );
    let root_cert = root.sign(tbs)?;
    let pem = |cert: &x509::Certificate| -> Result<String> {
        Ok(String::from_utf8(
            x509::PemBlock::new("CERTIFICATE", cert)?.to_bytes()?,
        )?)
    };
    let root = Ca::from_pem(&pem(&root_cert)?, &root.key_pem())?;
    let root_cert = root.sign(root_cert.tbs)?;
    let root = Ca::from_pem(&pem(&root_cert)?, &root.key_pem())?;
    let intermediate = Ca::new(fcx, "DigiCert Global G3 TLS ECC SHA384 2020 CA1")?;
    let mut tbs = x509::Certificate::parse(&intermediate.cert_der())?.tbs;
    tbs.validity = x509::Validity {
        not_before: x509::Time::from_unix(1618358400)?,
        not_after: x509::Time::from_unix(1933891199)?,
    };
    tbs.extensions
        .retain(|e| e.oid.as_bytes() != x509::oid::BASIC_CONSTRAINTS);
    tbs.extensions.push(
        x509::BasicConstraints {
            ca: true,
            path_len: Some(0),
        }
        .to_extension(true)?,
    );
    tbs.subject = home_name("DigiCert Global G3 TLS ECC SHA384 2020 CA1", false);
    let cert = root.sign(tbs)?;
    let intermediate = Ca::from_pem(&pem(&cert)?, &intermediate.key_pem())?;
    write_ca(dir, &intermediate)?;
    std::fs::write(dir.join("root.pem"), root.cert_pem())?;
    Ok(())
}
