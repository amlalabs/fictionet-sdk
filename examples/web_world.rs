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
use fictionet::stdlib::journal::Journal;
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
    runtime.block_on(fictionet::run(move |cx| async move { world(&cx, chain, key, attachments) }))
}

/// Builds the world's sites on `attachments`, with `chain` and `key` for
/// every HTTPS name.
fn world(
    cx: &fictionet::Cx,
    chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    attachments: fictionet::Attachments,
) -> Result {
    {
        let config = Arc::new(
            tls::config_builder(cx, SystemTime::now(), rustls::crypto::ring::default_provider())
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

        // One custom event per request and per query, for observers, from
        // the journal of everything the sites do.
        let journal = Journal::new().dashboard(false);
        let observer = cx.clone();
        journal.subscribe(move |e| {
            let cx = &observer;
            let sandbox = e.conn.sandbox.as_ref().map_or("", |s| &*s.name);
            if e.is("http", "request") {
                cx.event("http_request")
                    .str("sandbox", sandbox)
                    .str("method", e.str("method").unwrap_or(""))
                    .str("host", e.str("host").unwrap_or(""))
                    .str("path", e.str("path").unwrap_or(""))
                    .int("status", e.u64("status").unwrap_or(0) as i64)
                    .int("bytes", e.u64("sent").unwrap_or(0) as i64)
                    .emit();
            } else if e.is("dns", "query") {
                let answer = match e.str("answer") {
                    Some("addr") => e.str("addr").unwrap_or("").to_owned(),
                    Some("nodata") => "NoData".into(),
                    Some("nxdomain") => "NxDomain".into(),
                    Some("error") => format!("Error({})", e.u64("rcode").unwrap_or(0)),
                    _ => "None".into(),
                };
                cx.event("dns_query").str("sandbox", sandbox).str("name", e.str("name").unwrap_or("")).str("answer", &answer).emit();
            }
        });
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
        .journal(journal)
        .serve(cx, attachments)?;
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    //! What a client sees of the world, compared with a report recorded
    //! before the world moved onto the service layer
    //! (`examples/web_world.golden.txt`): DNS answers, and the status, the
    //! headers that matter and the body of each request.
    //!
    //! `WEB_WORLD_GOLDEN_WRITE=1 cargo test --example web_world` records it
    //! again.

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, mpsc};

    use bytes::Bytes;
    use fictionet::prelude::*;
    use fictionet::stdlib::dns::op::{Message, Query};
    use fictionet::stdlib::dns::rr::{Name, RData, RecordType};
    use fictionet::stdlib::{ip, tcp, udp};
    use fictionet::{Cx, End};
    use http_body_util::{BodyExt, Full};
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

    const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    struct Machine {
        tcp: tcp::Endpoint,
        udp: udp::Endpoint,
        _icmp: End,
    }

    async fn dns(cx: &Cx, m: &Machine, name: &str, kind: RecordType) -> String {
        let mut socket = m.udp.bind(40000 + (cx.random_u64() % 20000) as u16).unwrap();
        let mut q = Message::query();
        q.metadata.id = 7;
        q.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        socket.send_to(&q.to_vec().unwrap(), SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 53));
        let (bytes, _) = socket.recv(cx).await.unwrap();
        let r = Message::from_vec(&bytes).unwrap();
        let addrs: Vec<String> = r
            .answers
            .iter()
            .filter_map(|a| match &a.data {
                RData::A(a) => Some(a.0.to_string()),
                RData::AAAA(a) => Some(a.0.to_string()),
                _ => None,
            })
            .collect();
        format!("dns {name} {kind:?} {:?} {addrs:?}", r.metadata.response_code)
    }

    #[derive(Clone)]
    struct Spawn;
    impl<F: std::future::Future + Send + 'static> hyper::rt::Executor<F> for Spawn
    where
        F::Output: Send + 'static,
    {
        fn execute(&self, fut: F) {
            tokio::spawn(fut);
        }
    }

    /// One request; a line with what came back.
    async fn ask<IO>(io: IO, h2: bool, method: &str, uri: &str, host: &str, body: Vec<u8>) -> String
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(io);
        let request = http::Request::builder().method(method).uri(uri).header("host", host).body(Full::new(Bytes::from(body))).unwrap();
        let response = if h2 {
            let (mut send, conn) = hyper::client::conn::http2::handshake(Spawn, io).await.unwrap();
            tokio::spawn(conn);
            let (mut parts, body) = request.into_parts();
            parts.headers.remove("host");
            send.send_request(http::Request::from_parts(parts, body)).await.unwrap()
        } else {
            let (mut send, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
            tokio::spawn(conn);
            send.send_request(request).await.unwrap()
        };
        let status = response.status().as_u16();
        let version = response.version();
        let headers: Vec<String> = ["location", "content-length", "content-type", "transfer-encoding"]
            .iter()
            .filter_map(|h| response.headers().get(*h).map(|v| format!("{h}={}", v.to_str().unwrap())))
            .collect();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let shown = if body.len() > 200 { format!("<{} bytes>", body.len()) } else { format!("{:?}", String::from_utf8_lossy(&body)) };
        format!("{method} {host}{uri} {version:?} {status} {headers:?} {shown}")
    }

    async fn report(cx: &Cx, attacher: &fictionet::Attacher, roots: Arc<rustls::RootCertStore>) -> Vec<String> {
        let end = attacher.attach("agent").unwrap();
        let (t, u, i, _o) = ip::split_protocols(cx, end);
        let m = Machine { tcp: tcp::endpoint(cx, t, ME.into()), udp: udp::endpoint(cx, u, ME.into()), _icmp: i };
        let mut lines = Vec::new();
        for name in ["example.test", "www.example.test", "shared.test", "plain.test", "v4only.test", "v6only.test", "nope.test"] {
            lines.push(dns(cx, &m, name, RecordType::A).await);
            lines.push(dns(cx, &m, name, RecordType::AAAA).await);
        }
        let tls = |addr: IpAddr, sni: &'static str, alpn: &'static [u8]| {
            let roots = roots.clone();
            let m = &m;
            async move {
                let conn = m.tcp.connect(cx, SocketAddr::new(addr, 443)).await.unwrap();
                let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                config.alpn_protocols = vec![alpn.to_vec()];
                tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(ServerName::try_from(sni).unwrap(), conn.into_tokio(cx))
                    .await
                    .unwrap()
            }
        };
        let shared: IpAddr = super::SHARED.into();
        lines.push(ask(tls(shared, "example.test", b"http/1.1").await, false, "GET", "/", "example.test", vec![]).await);
        lines.push(ask(tls(shared, "example.test", b"h2").await, true, "GET", "https://example.test/", "example.test", vec![]).await);
        lines.push(ask(tls(shared, "example.test", b"http/1.1").await, false, "GET", "/count", "example.test", vec![]).await);
        lines.push(ask(tls(shared, "www.example.test", b"h2").await, true, "GET", "https://www.example.test/count", "www.example.test", vec![]).await);
        lines.push(ask(tls(shared, "example.test", b"http/1.1").await, false, "POST", "/upload", "example.test", vec![b'u'; 100_000]).await);
        lines.push(ask(tls(shared, "example.test", b"http/1.1").await, false, "HEAD", "/big", "example.test", vec![]).await);
        lines.push(ask(tls(shared, "example.test", b"http/1.1").await, false, "GET", "/nowhere", "example.test", vec![]).await);
        let plain = |addr: IpAddr| {
            let m = &m;
            async move { m.tcp.connect(cx, SocketAddr::new(addr, 80)).await.unwrap().into_tokio(cx) }
        };
        lines.push(ask(plain(shared).await, false, "GET", "/a?b=c", "example.test", vec![]).await);
        lines.push(ask(plain(shared).await, false, "GET", "/x", "shared.test", vec![]).await);
        lines.push(ask(plain(shared).await, false, "GET", "/x", "nope.test", vec![]).await);
        let auto: IpAddr = Ipv4Addr::new(198, 18, 0, 1).into();
        lines.push(ask(plain(auto).await, false, "GET", "/mb", "plain.test", vec![]).await);
        lines.push(ask(plain(auto).await, true, "GET", "http://plain.test/y", "plain.test", vec![]).await);
        lines.push(ask(plain(auto).await, false, "POST", "/upload", "plain.test", vec![b'v'; 3000]).await);
        let v4: IpAddr = Ipv4Addr::new(198, 18, 0, 2).into();
        lines.push(ask(tls(v4, "v4only.test", b"http/1.1").await, false, "GET", "/", "v4only.test", vec![]).await);
        lines
    }

    #[test]
    fn the_client_report_is_the_recorded_one() {
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca.self_signed(&ca_key).unwrap();
        let names = ["example.test", "www.example.test", "v4only.test", "v6only.test"];
        let mut leaf = CertificateParams::new(names.map(str::to_owned).to_vec()).unwrap();
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let roots = Arc::new(roots);
        let chain = vec![leaf.der().clone()];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
            let _ = rt.block_on(fictionet::run(move |cx| async move {
                let (attacher, attachments) = fictionet::attachments();
                super::world(&cx, chain, key, attachments)?;
                let lines = report(&cx, &attacher, roots).await;
                let _ = tx.send(lines);
                cx.cancel();
                Ok(())
            }));
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(120)).expect("the client finished");
        let file = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/web_world.golden.txt");
        let got = got.join("\n") + "\n";
        if std::env::var_os("WEB_WORLD_GOLDEN_WRITE").is_some() {
            std::fs::write(file, &got).unwrap();
            return;
        }
        assert_eq!(got, std::fs::read_to_string(file).unwrap());
    }
}
