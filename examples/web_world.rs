//! A small world of websites, written with `web::Sites`.
//!
//! ```text
//! cargo run --features tokio --example web_world -- /run/fictionet/world.sock /run/fictionet/ca.pem
//! ```
//!
//! It makes a certificate authority for the world when it starts and
//! writes its certificate to the second path, so the sandbox can trust it
//! (`curl --cacert`). Then it serves:
//!
//! The network is dual-stack: every site has an IPv4 and an IPv6 address,
//! except the two that test one family.
//!
//! - `example.test` and `www.example.test`: an axum app over HTTPS. `/`
//!   answers with the request's [`web::Target`] and HTTP version, `/count`
//!   with how many times it was asked, `/big` with 16 MiB, and a POST to
//!   `/upload` with how many bytes it got. Port 80 redirects to https.
//!   Both live at 203.0.113.10 and 2001:db8:113::10.
//! - `shared.test`: a plain HTTP site at the same addresses, with no TLS.
//! - `plain.test`: a plain HTTP site with addresses of its own, from
//!   `198.18.0.0/15` and `2001:2::/48`, with no TLS, so its port 443 is
//!   closed. `/mb` answers with 1 MiB, `/big` with 16 MiB, and a POST to
//!   `/upload` with how many bytes it got.
//! - `v4only.test` and `v6only.test`: the same app over HTTPS, with only
//!   an IPv4 or only an IPv6 address. DNS answers the other record type
//!   with NODATA.
//! - `upstream`: [`web::proxy()`], which forwards to the real host named
//!   `upstream` on the world's own network (a container in the Docker test).
//! - every other name: NXDOMAIN.
//!
//! Every HTTP request and DNS query is also sent to observers as a custom
//! event (`http_request`, `dns_query`). Watch them, and the whole world,
//! with `fictionet dashboard --world unix:<socket>`: see
//! [`fictionet::observe`].
//!
//! `web_world --upstream <port>` instead runs that real upstream: a tiny
//! HTTP server on the host's network that answers every request with
//! `hello from the real upstream`.
//!
//! The Docker test in `tests/docker/web` runs it with `fictionet attach`
//! and a sandbox with curl and dig.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use axum::Extension;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use fictionet::stdlib::tls;
use fictionet::stdlib::web;
use fictionet::Result;
use http::Version;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// The addresses `example.test`, `www.example.test` and `shared.test`
/// share.
const SHARED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
const SHARED6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0x113, 0, 0, 0, 0, 0x10);

fn main() -> Result {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--upstream") {
        let port = args.get(2).map(|p| p.parse()).transpose()?.unwrap_or(80);
        return upstream(port);
    }
    let path = args.get(1).cloned().unwrap_or_else(|| "/run/fictionet/world.sock".into());
    let ca_path = args.get(2).cloned().unwrap_or_else(|| "/run/fictionet/ca.pem".into());

    // The world's CA and one certificate for its HTTPS names.
    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // Python 3.13 and later check certificates strictly: a CA must say
    // what its key is for, and a leaf must name the key that signed it.
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name.push(rcgen::DnType::CommonName, "Fictionet web_world CA");
    let ca_key = KeyPair::generate()?;
    let ca = ca.self_signed(&ca_key)?;
    let names = ["example.test", "www.example.test", "v4only.test", "v6only.test"];
    let mut leaf = CertificateParams::new(names.map(str::to_owned).to_vec())?;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // Python 3.13 and later refuse a leaf without an authority key identifier.
    leaf.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate()?;
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key)?;
    std::fs::write(&ca_path, ca.pem())?;
    let chain = vec![leaf.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

    let (attacher, attachments) = fictionet::attachments();
    let _listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone().into()), attacher)?;
    println!("listening on {path}, CA in {ca_path}");

    // web::proxy() needs a tokio runtime polling the world.
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(fictionet::run(move |cx| async move {
        let config = Arc::new(
            tls::config_builder(&cx, SystemTime::now(), rustls::crypto::ring::default_provider())
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(chain, key)?,
        );
        let count = Arc::new(AtomicU64::new(0));
        let app = axum::Router::new()
            .route(
                "/",
                get(|Extension(t): Extension<web::Target>, version: Version| async move {
                    format!("hello from {} {} {} over {:?}\n", t.scheme, t.host, t.port, version)
                }),
            )
            .route(
                "/count",
                get(move || {
                    let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                    async move { format!("{n}\n") }
                }),
            )
            // 16 MiB, for measuring throughput.
            .route("/big", get(|| async { vec![b'x'; 16 << 20] }))
            .route("/upload", post(upload).layer(DefaultBodyLimit::disable()));
        let plain = axum::Router::new()
            .route("/mb", get(|| async { vec![b'x'; 1 << 20] }))
            .route("/big", get(|| async { vec![b'x'; 16 << 20] }))
            .route("/upload", post(upload).layer(DefaultBodyLimit::disable()))
            .fallback(|Extension(t): Extension<web::Target>| async move {
            format!("plain site {} {} {}\n", t.scheme, t.host, t.port)
        });

        // One custom event per request and per query, for observers.
        let observed = |cx: &fictionet::Cx, event: &web::Event| match event {
            web::Event::Http(h) => cx
                .event("http_request")
                .str("sandbox", &h.sandbox.name)
                .str("method", h.method.as_str())
                .str("host", h.host.as_deref().unwrap_or(""))
                .str("path", h.uri.path())
                .int("status", h.status.map_or(0, |s| s.as_u16()))
                .int("bytes", h.sent as i64)
                .emit(),
            web::Event::Dns(d) => cx
                .event("dns_query")
                .str("sandbox", &d.sandbox.name)
                .str("name", d.name.as_deref().unwrap_or(""))
                .str("answer", &match &d.answer {
                    web::DnsAnswer::Addr(a) => a.to_string(),
                    other => format!("{other:?}"),
                })
                .emit(),
            _ => {}
        };
        web::Sites::new(move |host: &str| {
            println!("lookup {host}");
            match host {
                "example.test" | "www.example.test" => Some(web::Site::new(app.clone()).at(SHARED).at(SHARED6).tls({
                    let c = config.clone();
                    move |_| c.clone()
                })),
                "v4only.test" => Some(web::Site::new(app.clone()).ipv4_only().tls({
                    let c = config.clone();
                    move |_| c.clone()
                })),
                "v6only.test" => Some(web::Site::new(app.clone()).ipv6_only().tls({
                    let c = config.clone();
                    move |_| c.clone()
                })),
                "shared.test" => Some(web::Site::new(plain.clone()).at(SHARED).at(SHARED6)),
                "plain.test" => Some(web::Site::new(plain.clone())),
                "upstream" => Some(web::Site::new(web::proxy())),
                _ => None,
            }
        })
        .on_event(observed)
        .serve(&cx, attachments)?;
        Ok(())
    }))
}

/// Reads a request body to its end and answers with its length, for
/// measuring uploads.
async fn upload(body: axum::body::Body) -> String {
    use http_body_util::BodyExt;
    let mut body = body;
    let mut n = 0usize;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(f) => n += f.data_ref().map_or(0, |d| d.len()),
            Err(e) => return format!("error after {n} bytes: {e}\n"),
        }
    }
    format!("{n}\n")
}

/// A real HTTP server on the host's network, for the proxy to reach.
fn upstream(port: u16) -> Result {
    let listener = std::net::TcpListener::bind(("0.0.0.0", port))?;
    println!("upstream listening on port {port}");
    for conn in listener.incoming() {
        let Ok(mut conn) = conn else { continue };
        std::thread::spawn(move || {
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let first = String::from_utf8_lossy(&request).lines().next().unwrap_or("").to_owned();
            println!("upstream got: {first}");
            let body = format!("hello from the real upstream: {first}\n");
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = conn.write_all(response.as_bytes());
        });
    }
    Ok(())
}
