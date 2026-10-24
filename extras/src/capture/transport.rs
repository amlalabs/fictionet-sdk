//! Public destinations are resolved once and pinned for each connection.

use super::BROWSER;
use crate::warc;
use std::{io, net::IpAddr};
use url::Url;

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

/// A client for one admitted destination. Redirects require a fresh admission;
/// environment proxies and URL credentials are never used.
pub async fn client(url: &Url) -> io::Result<reqwest::Client> {
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(io::Error::other("URL is not a public HTTP destination"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::other("missing HTTP host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::other("missing HTTP port"))?;
    let addresses: Vec<_> = tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
        .await?
        .collect();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !public_address(address.ip()))
    {
        return Err(io::Error::other(
            "destination is outside the public network",
        ));
    }
    reqwest::Client::builder()
        .user_agent(BROWSER)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(io::Error::other)
}

/// Receive a response's wire bytes, still content encoded.
pub async fn receive(mut response: reqwest::Response) -> io::Result<warc::Response> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        body.extend_from_slice(&chunk);
    }
    Ok(warc::Response {
        status: response.status(),
        headers: response.headers().clone(),
        body: body.into(),
    })
}
