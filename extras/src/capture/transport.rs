//! Public destinations are resolved once and pinned for each connection.

use super::BROWSER;
use crate::warc;
use std::{
    io,
    net::IpAddr,
    sync::{Arc, OnceLock},
};
use url::Url;

/// Reuse public connections without changing their pinned destinations.
#[derive(Clone, Default)]
pub struct Pool {
    clients:
        std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<url::Origin, reqwest::Client>>>,
}

impl Pool {
    /// Obtain the connection pool for this URL's origin.
    pub async fn client(&self, url: &Url) -> io::Result<reqwest::Client> {
        if !url.username().is_empty() || url.password().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "URL contains credentials",
            ));
        }
        let origin = url.origin();
        if let Some(client) = self.clients.lock().await.get(&origin) {
            return Ok(client.clone());
        }
        let host = url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing HTTP host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing HTTP port"))?;
        let addresses: Vec<_> = tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
            .await?
            .collect();
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|address| !public_address(address.ip()))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "destination is outside the public network",
            ));
        }
        let client = client(url).await?;
        Ok(self
            .clients
            .lock()
            .await
            .entry(origin)
            .or_insert(client)
            .clone())
    }
}

/// Whether an address belongs to the public Internet.
pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
                && !ip.is_broadcast()
                && !matches!(a, 0 | 224..=255)
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0 && c == 0)
                && !(a == 192 && b == 88 && c == 99)
                && !(a == 198 && matches!(b, 18 | 19))
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return public_address(ip.into());
            }
            let [a, b, ..] = ip.segments();
            (a & 0xe000) == 0x2000
                && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                && a != 0x2002
                && !(a == 0x3fff && b < 0x1000)
        }
    }
}

struct PublicDns;

impl reqwest::dns::Resolve for PublicDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .collect::<Vec<_>>();
            if addresses.is_empty()
                || addresses
                    .iter()
                    .any(|address| !public_address(address.ip()))
            {
                return Err(io::Error::other("destination is outside the public network").into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// A pooled client whose resolver admits and pins public destinations for each
/// connection. Redirects, environment proxies and URL credentials are disabled.
pub async fn client(url: &Url) -> io::Result<reqwest::Client> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "URL is not a public HTTP destination",
        ));
    }
    let host = url
        .host()
        .ok_or_else(|| io::Error::other("missing HTTP host"))?;
    let address = match host {
        url::Host::Domain(_) => None,
        url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
    };
    if address.is_some_and(|ip| !public_address(ip)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination is outside the public network",
        ));
    }
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let client = reqwest::Client::builder()
        .use_native_tls()
        .user_agent(BROWSER)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(PublicDns))
        .build()
        .map_err(io::Error::other)?;
    let _ = CLIENT.set(client.clone());
    Ok(client)
}

/// Retain the complete response representation.
pub async fn receive(response: reqwest::Response) -> io::Result<warc::Response> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.map_err(io::Error::other)?;
    Ok(warc::Response {
        status,
        headers,
        body,
    })
}
