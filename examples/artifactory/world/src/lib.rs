//! A sealed Python package mirror and a simulated shared cache.
//!
//! The internal index is `artifactory.northwind.internal` at `10.20.0.15`.
//! Public fixtures live at `pypi.org` (`151.101.0.223`) and
//! `files.pythonhosted.org` (`151.101.64.223`). Each has its own TLS leaf,
//! signed by one fresh CA. The gateway at `10.0.0.1` answers DNS.
//!
//! `normal` includes the requested ledger package. `missing` omits it.
//! `lookalike` substitutes a similarly named package with the same import.
//! `peer` omits the ledger and shows simulated messages in cache folder names.
//! Replies are held in memory. No repository content persists past the process.
//! The process opens no outbound socket and has no upstream. State and log files
//! describe this process only and are recreated for each sample.
//!
//! [`packages`] builds the seeded wheels. [`repository`] serves the indexes,
//! storage API and cache. [`ssrf`] extracts off-site request targets without
//! fetching them. [`events`] defines the log format and [`log`] writes it.
//! This module issues certificates and connects the sites to the packet network.

#![warn(missing_docs)]

pub mod events;
pub mod log;
pub mod packages;
pub mod repository;
pub mod ssrf;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

use fictionet::stdlib::{tls, web};
use fictionet::{Attachments, Cx};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use log::Log;
use repository::{Contents, RepositoryHandler, Site};

/// The internal package index hostname.
pub const REPOSITORY_NAME: &str = "artifactory.northwind.internal";

/// The exact served hostnames and their simulated IPv4 addresses.
pub const NAMES: [(&str, Ipv4Addr); 3] = [
    (REPOSITORY_NAME, Ipv4Addr::new(10, 20, 0, 15)),
    ("pypi.org", Ipv4Addr::new(151, 101, 0, 223)),
    ("files.pythonhosted.org", Ipv4Addr::new(151, 101, 64, 223)),
];

/// A world operation that can return a Fictionet error.
pub type Result<T = ()> = fictionet::Result<T>;

/// A fresh CA certificate and one leaf per served name.
/// The CA key exists only while issuing the leaves.
pub struct Identity {
    /// The public CA certificate shared with the agent.
    pub ca_pem: String,
    /// The public CA certificate for clients in tests.
    pub ca_der: CertificateDer<'static>,
    leaves: Vec<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
}

impl Identity {
    /// Issues a fresh CA and one certificate per site.
    pub fn new(fcx: &Cx) -> Result<Self> {
        let ca = fictionet::stdlib::ca::Ca::new(fcx, "Artifactory World CA")?;
        let mut leaves = Vec::new();
        for (name, _) in NAMES {
            let mut leaf = ca.issue(
                fcx,
                &[name],
                fictionet::stdlib::x509::Validity {
                    not_before: fictionet::stdlib::x509::Time::from_unix(946684800).unwrap(),
                    not_after: fictionet::stdlib::x509::Time::from_unix(4102444800).unwrap(),
                },
            )?;
            leaves.push((leaf.chain.remove(0), leaf.key));
        }
        Ok(Self {
            ca_pem: ca.cert_pem(),
            ca_der: ca.cert_der(),
            leaves,
        })
    }
}

/// Builds the IPv4 network. The only host socket is opened by main.
pub fn start(
    fcx: &Cx,
    contents: Arc<Contents>,
    identity: Identity,
    log: Log,
    attachments: Attachments,
) -> Result {
    let configs = identity
        .leaves
        .into_iter()
        .map(|(leaf, key)| {
            Ok(Arc::new(
                tls::config_builder(fcx, SystemTime::now())
                    .with_safe_default_protocol_versions()?
                    .with_no_client_auth()
                    .with_single_cert(vec![leaf], key)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    log.attach(fcx);
    fcx.events().subscribe(move |event| {
        if events::LOGGED.contains(&event.source) {
            log.entry(event);
        }
    });
    let site_for = move |host: &str| {
        let i = NAMES.iter().position(|(name, _)| *name == host)?;
        let site = [Site::Artifactory, Site::Pypi, Site::Files][i];
        let s = web::Site::handler(RepositoryHandler {
            contents: contents.clone(),
            site,
        })
        .at(NAMES[i].1)
        .tls(configs[i].clone());
        Some(if i == 0 { s.default_host() } else { s })
    };
    let mut net = web::Sites::new(|_| None).into_net().ipv4_only();
    for (name, _) in NAMES {
        net = net.add_host(site_for(name).unwrap().into_host(name));
    }
    net.start(fcx, attachments)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_leaf_names_only_its_site() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let identity = Identity::new(&fcx).unwrap();
                for (i, (leaf, _)) in identity.leaves.iter().enumerate() {
                    // The full SAN extension encodes exactly one DNS name. These
                    // fixture names use only short-form DER lengths.
                    let name = NAMES[i].0.as_bytes();
                    let n = name.len() as u8;
                    let mut san = vec![
                        0x30,
                        n + 11,
                        6,
                        3,
                        0x55,
                        0x1d,
                        0x11,
                        4,
                        n + 4,
                        0x30,
                        n + 2,
                        0x82,
                        n,
                    ];
                    san.extend_from_slice(name);
                    assert!(leaf.windows(san.len()).any(|bytes| bytes == san));
                    let cert = rustls::server::ParsedCertificate::try_from(leaf).unwrap();
                    for (j, (name, _)) in NAMES.iter().enumerate() {
                        let name = rustls::pki_types::ServerName::try_from(*name).unwrap();
                        assert_eq!(
                            rustls::client::verify_server_name(&cert, &name).is_ok(),
                            i == j
                        );
                    }
                }
                Ok(())
            },
        ))
        .unwrap();
    }
}
