//! Public certificate chains parsed from the identities the world actually serves.

use border_world::Identities;
use fictionet::stdlib::{
    codec::Wire,
    protocols::{
        asn1::{Reader, Rules},
        x509,
    },
    services::ca::Leaf,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Certificate {
    pub subject: String,
    pub names: Vec<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub key_type: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Chain {
    pub identity: &'static str,
    pub trusted_issuer: bool,
    pub certificates: Vec<Certificate>,
}

/// Fixed world data made once at startup. Only public DER is read; keys are never copied.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Certificates(pub Vec<Chain>);

impl Certificates {
    pub fn new(ids: &Identities) -> fictionet::Result<Self> {
        fn chain(
            identity: &'static str,
            leaf: &Leaf,
            trusted_issuer: bool,
        ) -> fictionet::Result<Chain> {
            let certificates = leaf
                .chain
                .iter()
                .map(|der| {
                    let tbs = x509::Certificate::parse(der)?.tbs;
                    let names = tbs
                        .get::<x509::SubjectAltName>()?
                        .map(|names| {
                            names
                                .0
                                .into_iter()
                                .filter_map(|name| match name {
                                    x509::GeneralName::Dns(s) => Some(s),
                                    other => other.ip_addr().map(|ip| ip.to_string()),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    Ok(Certificate {
                        subject: name(&tbs.subject),
                        names,
                        issuer: name(&tbs.issuer),
                        not_before: tbs.validity.not_before.text().into(),
                        not_after: tbs.validity.not_after.text().into(),
                        serial: tbs.serial.iter().map(|b| format!("{b:02x}")).collect(),
                        key_type: key_type(&tbs.public_key.algorithm)?,
                    })
                })
                .collect::<fictionet::Result<Vec<_>>>()?;
            Ok(Chain {
                identity,
                trusted_issuer,
                certificates,
            })
        }
        Ok(Self(vec![
            chain("bank", &ids.bank, true)?,
            chain("impostor", &ids.impostor, false)?,
            chain("status", &ids.status, true)?,
        ]))
    }
}

fn key_type(algorithm: &x509::AlgorithmIdentifier) -> fictionet::Result<String> {
    if algorithm.oid.as_bytes() == x509::oid::EC_PUBLIC_KEY {
        let mut reader = Reader::new(
            algorithm.parameters.as_deref().unwrap_or_default(),
            Rules::Der,
        );
        let curve = reader.read_oid()?;
        return Ok(match curve.as_bytes() {
            x509::oid::PRIME256V1 => "ECDSA P-256".into(),
            x509::oid::SECP384R1 => "ECDSA P-384".into(),
            _ => format!("Elliptic curve ({curve})"),
        });
    }
    Ok(match algorithm.oid.as_bytes() {
        x509::oid::ED25519 => "Ed25519".into(),
        x509::oid::RSA_ENCRYPTION => "RSA".into(),
        _ => algorithm.oid.to_string(),
    })
}

fn name(name: &x509::Name) -> String {
    name.rdns
        .iter()
        .flatten()
        .map(|a| {
            format!(
                "{}={}",
                a.oid,
                a.value.as_text().unwrap_or("non-text value")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chains_come_from_the_served_certificates() {
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(2)),
            |cx| async move {
                let ca = fictionet::stdlib::services::ca::Ca::new(
                    &cx,
                    border_world::certs::LAB_CA_NAME,
                )?;
                let ids = border_world::identities(&cx, &ca)?;
                let public = Certificates::new(&ids)?;
                assert_eq!(public.0.len(), 3);
                assert_eq!(
                    public.0[0].certificates[0].names,
                    public.0[1].certificates[0].names
                );
                assert!(public.0[0].trusted_issuer);
                assert!(!public.0[1].trusted_issuer);
                for (chain, leaf) in public.0.iter().zip([&ids.bank, &ids.impostor, &ids.status]) {
                    assert_eq!(chain.certificates.len(), leaf.chain.len());
                    for (public, der) in chain.certificates.iter().zip(&leaf.chain) {
                        let tbs = x509::Certificate::parse(der)?.tbs;
                        assert_eq!(public.subject, name(&tbs.subject));
                        assert_eq!(public.issuer, name(&tbs.issuer));
                        assert_eq!(public.not_before, tbs.validity.not_before.text());
                        assert_eq!(public.not_after, tbs.validity.not_after.text());
                        assert!(!public.serial.is_empty());
                        assert_eq!(public.key_type, "ECDSA P-256");
                    }
                }
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
    }
}
