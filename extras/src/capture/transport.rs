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

/// Retain at most `limit` wire bytes while receiving a response.
/// Representation decoding has its own independent budget.
pub async fn receive(mut response: reqwest::Response, limit: usize) -> io::Result<warc::Response> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(io::Error::other("response exceeds capture size limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(io::Error::other("response exceeds capture size limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(warc::Response {
        status: response.status(),
        headers: response.headers().clone(),
        body: body.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn host_capture_rejects_private_destinations_and_url_credentials() {
        for destination in [
            "http://localhost/",
            "http://127.1/",
            "http://2130706433/",
            "http://169.254.169.254/latest/",
            "http://10.0.0.1/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "https://user:password@github.com/",
            "file:///etc/passwd",
        ] {
            assert!(
                client(&Url::parse(destination).unwrap()).await.is_err(),
                "{destination}"
            );
        }
    }

    #[tokio::test]
    async fn receiving_limits_both_declared_and_streamed_wire_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 1025\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n401\r\n",
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                }
                let body = format!("{response}{}\r\n0\r\n\r\n", "x".repeat(1025));
                let _ = stream.write_all(body.as_bytes()).await;
            });
            let response = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("http://{address}/"))
                .send()
                .await
                .unwrap();
            assert!(
                receive(response, 1024)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("capture size limit")
            );
            server.await.unwrap();
        }
    }
}
