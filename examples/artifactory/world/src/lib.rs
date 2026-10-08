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

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime};

use fictionet::stdlib::{tls, web};
use fictionet::{Attacher, Attachments, Cx, End, Interface, Packet};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

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
    pub fn new() -> Result<Self> {
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "Artifactory World CA");
        let ca_key = KeyPair::generate()?;
        let ca = ca.self_signed(&ca_key)?;
        let mut leaves = Vec::new();
        for (name, _) in NAMES {
            let mut leaf = CertificateParams::new(vec![name.to_owned()])?;
            leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            leaf.use_authority_key_identifier_extension = true;
            let key = KeyPair::generate()?;
            let leaf = leaf.signed_by(&key, &ca, &ca_key)?;
            leaves.push((
                leaf.der().clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            ));
        }
        Ok(Self {
            ca_pem: ca.pem(),
            ca_der: ca.der().clone(),
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
    fcx.events().subscribe(move |event| {
        if events::LOGGED.contains(&event.source) {
            log.entry(event);
        }
    });
    web::Sites::new(move |host: &str| {
        let i = NAMES.iter().position(|(name, _)| *name == host)?;
        let site = [Site::Artifactory, Site::Pypi, Site::Files][i];
        let config = configs[i].clone();
        let s = web::Site::handler(RepositoryHandler {
            contents: contents.clone(),
            site,
        })
        .at(NAMES[i].1)
        .tls(move |_| config.clone());
        Some(if i == 0 { s.default_host() } else { s })
    })
    .ipv4_only()
    .serve(fcx, attachments)
}
/// Resolves the three names before listening, so direct IP connections work.
pub async fn look_up_all(fcx: &Cx, attacher: &Attacher) -> Result {
    let from = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 254), 40000);
    let gateway = Ipv4Addr::new(10, 0, 0, 1);
    let mut end: End = attacher
        .attach(events::LOOKUPS)
        .map_err(|e| fictionet::Error::msg(format!("lookups: {e}")))?;
    let names = NAMES.map(|(n, _)| n);
    let mut waiting: HashMap<u16, &str> = HashMap::new();
    for (i, name) in names.iter().enumerate() {
        let id = i as u16 + 1;
        end.send(Packet(dns_query_packet(from, gateway, id, name)));
        waiting.insert(id, name);
    }
    let mut sleep = pin!(fcx.sleep(Duration::from_secs(10)));
    while !waiting.is_empty() {
        let packet = poll_fn(|cx| {
            if let Poll::Ready(r) = end.poll_recv(fcx, cx) {
                return Poll::Ready(r.ok());
            }
            match sleep.as_mut().poll(cx) {
                Poll::Ready(_) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        let Some(packet) = packet else {
            let left: Vec<_> = waiting.values().collect();
            return Err(fictionet::Error::msg(format!("no DNS answer for {left:?}")));
        };
        let p = &packet.0;
        if p.len() < 28 + 12 || p[9] != 17 {
            continue;
        }
        let ihl = usize::from(p[0] & 0x0f) * 4;
        let dns = &p[ihl + 8..];
        let id = u16::from_be_bytes([dns[0], dns[1]]);
        let rcode = dns[3] & 0x0f;
        let answers = u16::from_be_bytes([dns[6], dns[7]]);
        if let Some(name) = waiting.remove(&id)
            && (rcode != 0 || answers != 1)
        {
            return Err(fictionet::Error::msg(format!(
                "DNS for {name}: rcode {rcode}, {answers} answers"
            )));
        }
    }
    Ok(())
}

/// An IPv4/UDP packet with an A query for `name`. The UDP checksum is zero,
/// which IPv4 allows.
fn dns_query_packet(from: SocketAddrV4, gateway: Ipv4Addr, id: u16, name: &str) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&id.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.extend_from_slice(&[0, 0, 1, 0, 1]);
    let udp_len = 8 + dns.len();
    let total = 20 + udp_len;
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0,
        0,
        0x40,
        0,
        64,
        17,
        0,
        0,
    ]);
    p.extend_from_slice(&from.ip().octets());
    p.extend_from_slice(&gateway.octets());
    fictionet::stdlib::ip::set_header_checksum(&mut p[..20]);
    p.extend_from_slice(&from.port().wrapping_add(id).to_be_bytes());
    p.extend_from_slice(&53u16.to_be_bytes());
    p.extend_from_slice(&(udp_len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&dns);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_leaf_names_only_its_site() {
        let identity = Identity::new().unwrap();
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
    }
}
